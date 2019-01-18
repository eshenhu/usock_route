/** 
 * Unix socket filter in kernel space 
 *  
 * In the kernel/usr space, there is no good solution for 
 * tracing the raw data via unix domain socket, either 
 * system-tap solution and PRE_LOADER solution has some native 
 * drawback. 
 *  
 * As tcpdump is de-factor tools used by the developer, it is 
 * better to route this message to IP layer, then we can re-use 
 * the richest tcpdump/wireshark lua script to parse the raw 
 * data further. 
 *  
 * This kernel module use `kprobe` to trap the unix domain 
 * socket handling function to re-route the message to a 
 * pre-allocated port in //localhost. 
 *  
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/kprobes.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>

#include <linux/ip.h>
#include <linux/in.h>

#include <linux/delay.h>
#include <linux/un.h>
#include <linux/unistd.h>
#include <linux/ctype.h>
#include <asm/unistd.h>
#include <linux/stat.h>
#include <linux/uaccess.h>
#include <linux/kfifo.h>
#include <linux/log2.h>
#include <linux/gfp.h>
#include <linux/hashtable.h>
#include <linux/string.h>
#include <linux/kthread.h>


#define	SYSFS_NODE_NAME "usock_filter"

/*
 *  store the data with | len | hashkey | value |
 *  	key_sock: store the sock pointer address
 */
const static unsigned int MAGIC_NUMBER = 0xF94E8B9B;

struct jprobe_kfifo_it {
	unsigned int magic;
	unsigned int len;
	struct sock *val_sock;
	void *val_data;
};

#define SIZE_OF_KFIFO_HDR (sizeof(unsigned int) + sizeof(unsigned int) \
			 + sizeof(unsigned long))

#define MAX_SIZE_KFIFO_DATA (PAGE_SIZE)

static struct socket *skt_client;
static struct sockaddr_in sockaddr_fixed;

static void jprobe_fin_sock_client(void);

//static DEFINE_MUTEX(jprobe_wr_mtx);
static DEFINE_SPINLOCK(jprobe_lock);

#define default_cache_size  1024 * 8

static int client_port = 0;
static int cache_size = default_cache_size;

static struct kfifo kfifo_cache;

struct jprobe_res_mem {
	unsigned long start;
	unsigned int order;
};
#define SND_BUF_SIZE_ORDER  0
#define SND_BUF_SIZE       (1 << SND_BUF_SIZE_ORDER) * PAGE_SIZE

static struct jprobe_res_mem res_mem = { 0, 0 };
static struct jprobe_res_mem res_buf = { 0, 0 };

enum jprobe_sysfs_direct {
	JPROBE_SYSFS_SEND,
	JPROBE_SYSFS_RCV
};

struct jprobe_hlist {
	unsigned long sock;
	struct sockaddr_in in;
	unsigned int pid;
	unsigned int fd;
	enum jprobe_sysfs_direct direct;
	struct hlist_node hash_list;
};

static DEFINE_HASHTABLE(res_sock_kv, 3);

struct jprobe_res_mod {
	struct task_struct *th;
};

static struct jprobe_res_mod res_mod = { NULL };

static struct kobject *jprobe_kobject;

#define wait_timeout_x(task_state, msecs)	\
do {						\
	set_current_state((task_state));	\
	schedule_timeout((msecs) * HZ / 1000);	\
} while (0)

#define wait_timeout(msecs)	wait_timeout_x(TASK_INTERRUPTIBLE, (msecs))

#define POLLING_INTERVAL 500
#define JPROBE_POLLING_THREAD "jprobe_polling"

module_param(client_port, int, 0644);
MODULE_PARM_DESC(client_port, "specify client port, leave it alone if let "
	"module dyn assign");

module_param(cache_size, int, 0644);
MODULE_PARM_DESC(cache_size, "cache size(must be the order of PAGE_SIZE default"
	" is 2 if PAGE_SIZE = 4k]");

/*
 *
 */

static int jprobe_kfifo_init(void)
{
	res_mem.order = roundup_pow_of_two(cache_size / PAGE_SIZE);
	unsigned int cache_size_up = (1 << res_mem.order) * PAGE_SIZE;

	res_mem.start = __get_free_pages(GFP_KERNEL, res_mem.order);
	if (!res_mem.start) {
		printk(KERN_INFO "jprobe_sock: kfifo init cache failed\n");
		return -1;
	}

	kfifo_init(&kfifo_cache, (void *)res_mem.start, cache_size_up);

	printk(KERN_INFO "jprobe_sock: kfifo init finished\n");
	return 0;
}

static void jprobe_kfifo_free(void)
{
	kfifo_reset(&kfifo_cache);
	if (res_mem.start)
		free_pages(res_mem.start, res_mem.order);
}

static int jprobe_snd_buf_init(void)
{
	res_buf.order = SND_BUF_SIZE_ORDER;
	res_buf.start = __get_free_pages(GFP_KERNEL, res_buf.order);
	if (!res_buf.start) {
		printk(KERN_INFO "jprobe_sock:jprobe snd_buf init cache"
			" failed\n");
		return -ENOMEM;
	}
	printk(KERN_INFO "jprobe_sock: jprobe snd_buf init finished\n");
	return 0;
}

static void jprobe_snd_buf_free(void)
{
	if (res_buf.start)
		free_pages(res_buf.start, res_buf.order);
}

/*
 * @para:
 * 	ipaddr_ascii: ip address with ascii format
 * 	port:         public port for sock client (nl order)
 */
static int jprobe_util_get_free_port(unsigned short *port)
{
	int error = 0;
	struct socket *res_sock_hlp =
		(struct socket *)kmalloc(sizeof(struct socket), GFP_KERNEL);
	if (!res_sock_hlp) {
		printk(KERN_INFO "jprobe: sock_create failed\n");
		return -ENOMEM;
	}

	error = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &res_sock_hlp);
	if (error < 0) {
		printk(KERN_INFO "jprobe: sock_create failed, return %d\n",
			error);
		return -ENOMEM;
	}

	struct sockaddr_in addr_client;
	addr_client.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	//addr_client.sin_addr.s_addr = htonl(INADDR_ANY);
	//addr_client.sin_addr.s_addr = addr;
	addr_client.sin_family = AF_INET;
	addr_client.sin_port = 0;

	error = res_sock_hlp->ops->bind(res_sock_hlp,
		(struct sockaddr *)&addr_client,
		sizeof(addr_client));
	if (error < 0) {
		printk(KERN_INFO "jprobe: bind failed,return "
			"%d\n", error);
		goto out;
	}

	struct sockaddr_in addr_bind;
	int addr_len;
	error = res_sock_hlp->ops->getname(res_sock_hlp,
		(struct sockaddr *)&addr_bind,
		&addr_len, 0);
	if (error < 0) {
		printk(KERN_INFO "jprobe: failed to get free port with %d\n",
			error);
		goto out;
	}
	*port = ntohs(addr_bind.sin_port);

	printk(KERN_INFO "jprobe: get free port on ipaddr:port %pISpc with %d\n",
		&addr_client, *port);
out:
	sock_release(res_sock_hlp);
	res_sock_hlp = NULL;

	return error;
}

/**
 */
static struct jprobe_hlist* jprobe_kv_get_raw(unsigned int pid,
	unsigned int fd,
	enum jprobe_sysfs_direct direc)
{
	int bkt;
	struct jprobe_hlist *list_it, *list = NULL;
	rcu_read_lock();
	hash_for_each_rcu(res_sock_kv, bkt, list_it, hash_list) {
		if (list_it->pid == pid
			&& list_it->fd  == fd
			&& list_it->direct == direc) {
			list = list_it;
			break;
		}
	}
	rcu_read_unlock();
	return list;
}
/**
 * 
 */
static int jprobe_kv_get(struct sock *sock,
	struct sockaddr_in *in)
{
	int bkt;
	struct jprobe_hlist *list;
	int ret = -1;

	rcu_read_lock();
	hash_for_each_rcu(res_sock_kv, bkt, list, hash_list) {
		if (list->sock == (unsigned long)sock) {
			*in = list->in;
			ret = 0;
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}

/**
 * 
 */
static int jprobe_kv_get_by_direct(struct sock *sock,
	enum jprobe_sysfs_direct direct,
	struct sockaddr_in *in)
{
	int bkt;
	struct jprobe_hlist *list;
	int ret = -1;

	rcu_read_lock();
	hash_for_each_rcu(res_sock_kv, bkt, list, hash_list) {
		if (list->sock == (unsigned long)sock
			&& list->direct == direct) {
			*in = list->in;
			ret = 0;
			break;
		}
	}
	rcu_read_unlock();

	return ret;
}
/**
 * 
 * @param pid 
 * @param fd 
 * 
 * @return struct sock* 
 */
static struct sock* jprobe_kv_get_sock(unsigned int pid, unsigned int fd)
{
	struct sock *sock_found = NULL;
	int ret = -EINVAL;

	struct pid *pid_find = find_get_pid(pid);
	struct task_struct *task = get_pid_task(pid_find, PIDTYPE_PID);
	if (!task) {
		ret = -ESRCH;
		goto out1;
	}

	struct file *file = NULL;

	task_lock(task);
	rcu_read_lock();

	if (task->files) {
		file = fcheck_files(task->files, fd);
		if (file) {
			struct inode *inode = file_inode(file);

			if (!S_ISSOCK(inode->i_mode)) {
				ret = -ENOTSOCK;
				goto out2;
			}

			struct socket *sock = SOCKET_I(inode);
#if 1
			printk(KERN_INFO "jprobe: kv_get_sock find sock=0x%px [pid= %d fd= %d]", sock->sk, pid, fd);
#endif
			sock_found = sock->sk;
			if (sock_found && sock->ops && sock->ops->family != AF_UNIX) {
				ret = -EINVAL;
				goto out2;
			}
			//sock_hold(sock_found);
			ret = 0;
		}
	}
out2:
	rcu_read_unlock();
	task_unlock(task);

out1:
	put_task_struct(task);

	if (!ret)
		return sock_found;
	else
		return ERR_PTR(ret);
}
/**
 * 
 */
static int jprobe_kv_add(unsigned int pid,
	unsigned int fd,
	enum jprobe_sysfs_direct direc)
{
	if (jprobe_kv_get_raw(pid, fd, direc)) {
		printk(KERN_WARNING "jprobe: [pid %d fd %d direc %d] had already existed\n",
			pid, fd, direc);
		return -1;
	}
	struct sock *sock_fnd = jprobe_kv_get_sock(pid, fd);
	if (IS_ERR(sock_fnd)) {
		printk(KERN_WARNING "jprobe: unable to get sock addr with err %ld\n",
			PTR_ERR(sock_fnd));
		return -1;
	}
	unsigned long sock = (unsigned long)sock_fnd;

	unsigned short port;
	int err = jprobe_util_get_free_port(&port);
	if (err) {
		printk(KERN_WARNING "jprobe: failed to get free port\n");
		return err;
	}

	struct jprobe_hlist *list = kmalloc(sizeof(struct jprobe_hlist), GFP_KERNEL);
	if (!list) {
		printk(KERN_WARNING "jprobe: kmalloc failed\n");
		return -2;
	}

	list->sock = sock;
	list->pid = pid;
	list->fd = fd;
	list->direct = direc;

	list->in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	list->in.sin_family = AF_INET;
	list->in.sin_port = htons(port);

	hash_add_rcu(res_sock_kv, &list->hash_list, list->sock);

	return 0;
}

/**
 * 
 */
static int jprobe_kv_remove(unsigned int pid, unsigned int fd, char direc)
{
	int bkt;
	struct jprobe_hlist *list_it;
	struct hlist_node *tmp;

	hash_for_each_safe(res_sock_kv, bkt, tmp, list_it, hash_list){
		if (list_it->pid == pid
		    && list_it->fd  == fd
		    && list_it->direct == direc) {
			hlist_del(&list_it->hash_list);
			synchronize_rcu();
			kfree(list_it);
			break;
		}
	}
	return 0;
}

static void jprobe_kv_clear()
{
	int bkt;
	struct jprobe_hlist *list_it;
	struct hlist_node *tmp;

	hash_for_each_safe(res_sock_kv, bkt, tmp, list_it, hash_list){
		hlist_del(&list_it->hash_list);
		synchronize_rcu();
		kfree(list_it);
	}
}

static int jprobe_kfifo_copy_from_user(unsigned long sock_addr, const struct iovec *iovec, int len)
{
	int ret = 0;
	unsigned long flags;
	int len_copied = 0;

	static int cnt_push = 0;
	++cnt_push;

	int len_raw = len + SIZE_OF_KFIFO_HDR;

	WARN_ON(len_raw > MAX_SIZE_KFIFO_DATA);

	if (len_raw >  MAX_SIZE_KFIFO_DATA)
		len_raw = MAX_SIZE_KFIFO_DATA;

	spin_lock_irqsave(&jprobe_lock, flags);
	/* take the first element _len_ in struct jprobe_kfifo_it into accout */
	if (kfifo_avail(&kfifo_cache) < len_raw) {
		ret = -EINVAL;
		goto goto_kfifo_cp_end;
	}

	kfifo_in(&kfifo_cache, &MAGIC_NUMBER, sizeof(int));
	kfifo_in(&kfifo_cache, &len_raw, sizeof(int));
	kfifo_in(&kfifo_cache, &sock_addr, sizeof(unsigned long));

	while (len > 0) {
		kfifo_from_user(&kfifo_cache, iovec->iov_base, iovec->iov_len, &len_copied);
		len -= iovec->iov_len;
		++iovec;
	}
goto_kfifo_cp_end:
	spin_unlock_irqrestore(&jprobe_lock, flags);

	printk(KERN_INFO "jprobe_sock: kfifo push cycle %d , aviliable size %d with ret=%d\n",
		cnt_push, kfifo_avail(&kfifo_cache), ret);
	return ret;
}

static int jprobe_kfifo_copy_to_buf(char *buf, const unsigned int size)
{
	static int cnt_pop = 0;
	++cnt_pop;

	int ret = 0;
	unsigned int magic_number = 0;
	int len_rdout = kfifo_out_peek(&kfifo_cache, &magic_number, sizeof(unsigned int));
	if (len_rdout != sizeof(unsigned int)) {
		ret = -EINVAL;
		goto goto_kfifo_to_end;
	}

	if (magic_number != MAGIC_NUMBER) {
		printk(KERN_INFO "jprobe_sock: kfifo pop cycle %d , magic number missed 0x%x\n",
			cnt_pop, magic_number);
		kfifo_reset(&kfifo_cache);
		goto goto_kfifo_to_end;
	}

	char head[SIZE_OF_KFIFO_HDR] = { 0 };
	len_rdout = kfifo_out_peek(&kfifo_cache, &head, SIZE_OF_KFIFO_HDR);
	if (len_rdout != SIZE_OF_KFIFO_HDR) {
		ret = -EINVAL;
		goto goto_kfifo_to_end;
	}

	/* no any data inside */
	struct jprobe_kfifo_it *p = (struct jprobe_kfifo_it *)head;
	int len_raw = p->len;

	WARN_ON(len_raw < SIZE_OF_KFIFO_HDR || len_raw > size);

	if (len_raw < SIZE_OF_KFIFO_HDR) {
		ret = -EINVAL;
		goto goto_kfifo_to_end;
	}

	WARN_ON(len_raw > size);
	if (len_raw > size)
		len_raw = size;

	len_rdout = kfifo_out(&kfifo_cache, buf, len_raw);
	if (len_rdout != len_raw) {
		ret = -EINVAL;
		goto goto_kfifo_to_end;
	}
	ret = len_rdout;

goto_kfifo_to_end:
	printk(KERN_INFO "jprobe_sock: kfifo pop cycle %d , aviliable size %d\n",
		cnt_pop, kfifo_avail(&kfifo_cache));
	return ret;
}
/*
 * @para:
 * 	ipaddr_ascii: ip address with ascii format
 * 	port:         public port for sock client
 */

int jprobe_setup_sock_client(const char *ipaddr_ascii, int port)
{
	skt_client = (struct socket *)kmalloc(sizeof(struct socket), GFP_KERNEL);
	int error = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &skt_client);
	if (error < 0) {
		printk(KERN_INFO "jprobe_setup_sock_client failed, return %d\n",
			error);
		return -ENOTSOCK;
	}
	/*
	struct in_addr_t addr = inet_addr(ipaddr_ascii);
	if (addr == INADDR_NONE){
		printk(KERN_INFO "jprobe_setup_sock_client para ipaddr_ascii"
			"traslate from %s error\n", ipaddr_ascii);
		return -1;
	}
	*/
	struct sockaddr_in addr_client;
	addr_client.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	//addr_client.sin_addr.s_addr = htonl(INADDR_ANY);
	//addr_client.sin_addr.s_addr = addr;
	addr_client.sin_family = AF_INET;
	addr_client.sin_port = htons(port);

	error = skt_client->ops->bind(skt_client, (struct sockaddr *)&addr_client,
		sizeof(addr_client));
	if (error < 0) {
		printk(KERN_INFO "jprobe_setup_sock_client bind failed,return "
			"%d\n", error);

		sock_release(skt_client);
		skt_client = NULL;
		return -EADDRINUSE;
	}

	printk(KERN_INFO "jprobe_setup_sock_client setup sock client on "
		"ipaddr:port %pISpc\n", &addr_client);
	return 0;
}

static void jprobe_fin_sock_client(void)
{
	if (skt_client) {
		sock_release(skt_client);
		skt_client = NULL;
	}
}

static int jprobe_common_msg_handle(struct sock *sock,
				    struct msghdr *msg,
				    size_t len,
				    enum jprobe_sysfs_direct direc)
{
	printk(KERN_INFO "jprobe_sock: sock = 0x%px, size = %zu\n", sock, len);

	if (!len)
		goto jprobe_common_exit;

	struct sockaddr_in in;
	if (!jprobe_kv_get_by_direct(sock, direc, &in)) {
		if (len > SND_BUF_SIZE - SIZE_OF_KFIFO_HDR) {
			printk(KERN_INFO "jprobe_sock: %zu larger than pre-defined value\n",
				len);
			goto jprobe_common_exit;
		}

		if (jprobe_kfifo_copy_from_user((unsigned long)sock, msg->msg_iov, len))
			printk(KERN_INFO "jprobe_sock: failed to push data into kfifo\n");


		#if 0
		static char buf[1200] = {0};
		int len_rd = jprobe_kfifo_copy_to_buf(buf, 1200);
		
		if (len_rd < 0)
			goto jprobe_common_exit;

		printk(KERN_INFO "jprobe_sock: copy_from_user len = %d "
		    "iov_len = %zu sock 0x%px\n",
		    len_rd, len, ((struct jprobe_kfifo_it *)buf)->val_sock);
		#endif
	}

jprobe_common_exit:
	return 0;
}

static int jprobe_unix_dgram_sendmsg(struct kiocb *kiocb, struct socket *sock,
	struct msghdr *msg, size_t len)
{
	jprobe_common_msg_handle(sock->sk, msg, len, JPROBE_SYSFS_SEND);
	jprobe_return();
	return 0;
}

static int jprobe_unix_dgram_recvmsg(struct kiocb *kiocb, struct socket *sock,
	struct msghdr *msg, size_t len, int flag)
{
	jprobe_common_msg_handle(sock->sk, msg, len, JPROBE_SYSFS_RCV);
	jprobe_return();
	return 0;
}

static int jprobe_polling_thread(void *data){
	while(!kthread_should_stop()){
		/* It will be better triggered by meet 2 rules in both:
		   1. Message in the FIFO reached the theshold.
		   2. The MAX time interval expired.
		*/
		wait_timeout(POLLING_INTERVAL);

		//printk(KERN_INFO "jprobe: polling at %dms", jiffies_to_msecs(jiffies));

		/* multi producer and one consumer for this kfifo*/
		while (!kfifo_is_empty(&kfifo_cache)){
			int len_rd = jprobe_kfifo_copy_to_buf((char*)(res_buf.start),
							      (unsigned int)SND_BUF_SIZE);
			if (len_rd < 0){
				printk(KERN_INFO "jprobe_sock: polling thead read non-valid data from kfifo\n");
				break;
			}

			struct sockaddr_in in;
			struct jprobe_kfifo_it *it = (struct jprobe_kfifo_it*)(res_buf.start);
			int ret = jprobe_kv_get(it->val_sock, &in);
			if (ret) {
				printk(KERN_INFO "jprobe: periodical job not find sock %px\n",
				       it->val_sock);
				continue;
			}

			struct msghdr msg;
			struct kvec iov[1];

			int len_snd = it->len - SIZE_OF_KFIFO_HDR;
			iov[0].iov_base = it->val_data;
			iov[0].iov_len = len_snd;

			msg.msg_control = NULL;
			msg.msg_controllen = 0;
			msg.msg_flags = 0;
			msg.msg_name = &in;
			msg.msg_namelen = sizeof(struct sockaddr_in);

			if (skt_client)
				kernel_sendmsg(skt_client, &msg, &iov[0], 1, iov[0].iov_len);
		}
	}
	return 0;
}

/**
 * jprobe_attr_filter_show() - provides current reset state through sysfs
 * 	Format: PID FD S|R (S stand 'send' R stand 'receive')
 * 		f.g. 12345 5 S;   12345 4 R;
 */
static ssize_t jprobe_attr_filter_show(struct kobject *kobj,
	struct kobj_attribute *attr,
	char *buf)
{
	int n = 0;
	int bkt;
	struct jprobe_hlist *list;

	rcu_read_lock();
	hash_for_each_rcu(res_sock_kv, bkt, list, hash_list) {
		n += sprintf(buf + n, "%d %d %c %u\n", list->pid, list->fd,
			list->direct == JPROBE_SYSFS_SEND ? 'S' : 'R',
			ntohs(list->in.sin_port));
	}
	rcu_read_unlock();

	return n;
}

/**
 * jprobe_attr_filter_store() - sets new reset state
 * 	Format: PID FD S|R (S stand 'send' R stand 'receive')
 * 		f.g. 12345 5 S;   12345 4 R;
 */
static ssize_t jprobe_attr_filter_store(struct kobject *kobj,
	struct kobj_attribute *attr,
	const char *buf, size_t count)
{

	unsigned int pid = 0;
	unsigned int fd = 0;
	char direction;

	char *line = NULL;
	int rc = 0;

	char *buf_move = (char *)buf;
	while ((line = strsep(&buf_move, "\n")) != NULL) {
		printk(KERN_INFO "jprobe: store %s\n", line);
		rc = sscanf(line, "%d %d %c", &pid, &fd, &direction);
		if (rc != 3) {
			printk(KERN_ERR "No expected fmt value, expected #PID FD S/R#");
			continue;
		}
		if (!(direction == 'S' || direction == 'R')) {
			printk(KERN_ERR "No expected fmt direc value, expected #S/R#");
			continue;
		}

		enum jprobe_sysfs_direct direc =
			direction == 'S' ? JPROBE_SYSFS_SEND : JPROBE_SYSFS_RCV;

		rc = jprobe_kv_add(pid, fd, direc);
		if (rc) {
			printk(KERN_ERR "jprobe: kv_add failed with %d\n", rc);
			continue;
		}
	}
	return count;
}

/**
 * jprobe_attr_count_show() - provides current reset state through sysfs
 */
static ssize_t jprobe_attr_count_show(struct kobject *kobj,
	struct kobj_attribute *attr,
	char *buf)
{
	return 0;
}

/*
 * jprobe_attributes - sysfs attribute definition array
 */
static struct kobj_attribute jprobe_attributes[] = {
	__ATTR(usock_filter, 0666,
	       jprobe_attr_filter_show, jprobe_attr_filter_store),
	__ATTR(usock_count, 0444,
	       jprobe_attr_count_show, NULL),
};

/*
 * jprobe_attrs - sysfs attributes for attribute group
 */
static struct attribute *jprobe_attrs[] = {
	&jprobe_attributes[0].attr,
	&jprobe_attributes[1].attr,
	NULL,
};

/*
 * jprobe_attr_group - driver sysfs attribute group
 */
static struct attribute_group jprobe_attr_group = {
	.attrs = jprobe_attrs,
};

/**
 * jprobe_create_sysfs_node() - creates sysfs nodes for control
 *
 * Function exports two control nodes: 
 *   1. filter list (pid-fd)	
 */
static int jprobe_create_sysfs_node(void)
{
	int retval;

	printk(KERN_DEBUG "Creating sysfs node");

	jprobe_kobject = kobject_create_and_add(SYSFS_NODE_NAME, firmware_kobj);
	printk(KERN_DEBUG "jprobe_kobject=%p", jprobe_kobject);
	if (!jprobe_kobject)
		return -ENOMEM;

	retval = sysfs_create_group(jprobe_kobject, &jprobe_attr_group);
	printk(KERN_DEBUG "sysfs_create_group() returned %d", retval);
	if (retval)
		kobject_put(jprobe_kobject);

	return retval;
}

/**
 * jprobe_remove_sysfs_node() - removes sysfs nodes
 */
static void jprobe_remove_sysfs_node(void)
{
	printk(KERN_DEBUG "Removing sysfs node");
	if (jprobe_kobject) {
		sysfs_remove_group(jprobe_kobject, &jprobe_attr_group);
		kobject_put(jprobe_kobject);
		jprobe_kobject = NULL;
	}
}

static struct jprobe jprobe_usock_dgram_send = {
	.entry			= jprobe_unix_dgram_sendmsg,
	.kp = {
		.symbol_name	= "unix_dgram_sendmsg",
	},
};

static struct jprobe jprobe_usock_dgram_recv = {
	.entry			= jprobe_unix_dgram_recvmsg,
	.kp = {
		.symbol_name	= "unix_dgram_recvmsg",
	},
};

static int __init jprobe_sock_init(void)
{
	int ret = register_jprobe(&jprobe_usock_dgram_send);
	if (ret < 0) {
		printk(KERN_INFO "register_jprobe_sock failed, returned %d\n", ret);
		return -1;
	}
	printk(KERN_INFO "Planted jprobe_sock at %p, handler addr %p\n",
		jprobe_usock_dgram_send.kp.addr, jprobe_usock_dgram_send.entry);

	ret = register_jprobe(&jprobe_usock_dgram_recv);
	if (ret < 0) {
		printk(KERN_INFO "register_jprobe_sock recv failed, returned %d\n", ret);
		return -1;
	}
	printk(KERN_INFO "Planted jprobe_sock at %p, handler addr %p\n",
		jprobe_usock_dgram_recv.kp.addr, jprobe_usock_dgram_recv.entry);

	int err = jprobe_setup_sock_client("127.0.0.1", client_port);
	if (err < 0) {
		printk(KERN_INFO "jprobe_setup_sock_client failed with err %d\n", err);
		goto out0;
	}

	//mutex_init(&jprobe_wr_mtx);
	err = jprobe_kfifo_init();
	if (err < 0) {
		printk(KERN_INFO "jprobe: failed with err %d\n", err);
		goto out1;
	}

	err = jprobe_snd_buf_init();
	if (err < 0) {
		printk(KERN_INFO "jprobe: snd_buf_init failed with err %d\n", err);
		goto out2;
	}

	/* debug purpose, forward to a fixed dst addr*/
	if (1) {
		sockaddr_fixed.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sockaddr_fixed.sin_family = AF_INET;
		sockaddr_fixed.sin_port = htons(60010);
	}

	jprobe_create_sysfs_node();

	res_mod.th = kthread_run(jprobe_polling_thread, NULL,
				 JPROBE_POLLING_THREAD);
	if (IS_ERR(res_mod.th)) {
		printk(KERN_INFO "Unable to start polling thread\n");
		ret = PTR_ERR(res_mod.th);
		goto out3;
	}

	return 0;

out3:
	jprobe_snd_buf_free();
out2:
	jprobe_kfifo_free();
out1:
	jprobe_fin_sock_client();
out0:
	printk(KERN_DEBUG "jprobe_sock_init failed\n");
	return ret;
}

static void __exit jprobe_sock_exit(void)
{
	unregister_jprobe(&jprobe_usock_dgram_send);
	unregister_jprobe(&jprobe_usock_dgram_recv);

	if (res_mod.th)
		kthread_stop(res_mod.th);

	jprobe_kv_clear();
	jprobe_kfifo_free();
	jprobe_snd_buf_free();
	jprobe_fin_sock_client();
	jprobe_remove_sysfs_node();

	printk(KERN_INFO "jprobe at 0x%p unregistered\n", jprobe_usock_dgram_send.kp.addr);
}

module_init(jprobe_sock_init);
module_exit(jprobe_sock_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("eshenhu <eshenhu@gmail.com>");
MODULE_DESCRIPTION("simple unix domain socket tracer tools");
