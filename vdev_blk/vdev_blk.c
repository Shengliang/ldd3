/*
 * Example: Kernel bio interface
 *          Tested with the simple block device.
 * --- Begin cut -- Makefile --
obj-m := vdev_module.o
vdev_module-objs = vdev_blk.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
kmodule:
 $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
 $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean

load:
 sudo insmod vdev_module.ko

rm:
 sudo rmmod vdev_module.ko
 * --- End cut -- Makefile --
 */
#include <linux/module.h> /* Specifically, a module */
#include <linux/kernel.h> /* We're doing kernel work */
#include <linux/init.h>         /* modules_init/_exit macros */
#include <linux/kthread.h> /* kthread_run*/
#include <linux/sched.h> /* task_struct*/
#include <linux/delay.h> /* mdelay()*/
#include <linux/vmalloc.h>      /* vzalloc */

#include <linux/fs.h> /* WRITE_SYNC */
#include <linux/blkdev.h>

#define kmem_virt(ptr) \
   (((ptr) >= (void*) VMALLOC_START) && \
	((ptr) < (void*) VMALLOC_END))

#define HAVE_BLKDEV_GET_BY_PATH 1    /*ubuntu 12.04 */
//#define HAVE_OPEN_BDEV_EXCLUSIVE 1 /* CentOS 6.4 */

#if defined(HAVE_BLKDEV_GET_BY_PATH)

#define my_blkdev_get_by_path(path, md, hld)   blkdev_get_by_path(path, \
                                            (md) | FMODE_EXCL, hld)
#define my_blkdev_close(bdev, md)       blkdev_put(bdev, (md) | FMODE_EXCL)

#elif defined(HAVE_OPEN_BDEV_EXCLUSIVE)

#define my_blkdev_get_by_path(path, md, hld)   open_bdev_exclusive(path, md, hld)
#define my_blkdev_close(bdev, md)       close_bdev_exclusive(bdev, md)

#else

#define my_blkdev_get_by_path(path, md, hld)   open_bdev_excl(path, md, hld)
#define my_blkdev_close(bdev, md)       close_bdev_excl(bdev)

#endif /* HAVE_BLKDEV_GET_BY_PATH | HAVE_OPEN_BDEV_EXCLUSIVE */

int lba_buf_zero(void* buf, int sz);
int lba_buf_fill(uint64_t seed, void* buf, int sz);
int lba_buf_comp(uint64_t seed, void* buf, int sz);
int lba_buf_dump(uint64_t lba, void* buf, int sz);

 
MODULE_LICENSE("Dual BSD/GPL");

/*
 * debug macro
 */
#define DEBUG
//#undef DEBUG

#ifdef DEBUG
#define DPRINT(fmt,args...) printk(KERN_INFO "%s,%i:" fmt "\n", \
                            __FUNCTION__, __LINE__,##args);
#else
#define DPRINT(fmt,args...)
#endif

/** @brief cache memory size */
#define CACHE_MEM_SIZE 256
//#define MAX_TAG (CACHE_MEM_SIZE)
#define MAX_TAG 2

/** @brief sector size */
#define SECTOR_SIZE 4096 
#define SECTOR_PER_BIO 4
#define NUM_BIO_PER_REQUEST 2

/** @brief cache memory array */
uint8_t * cache_mem;
uint8_t * v_mem;
uint8_t wr_done[MAX_TAG];
uint8_t rd_done[MAX_TAG];
uint8_t status[MAX_TAG];

/*
 * data package passed to threads
 */
typedef struct vblk_device
{
   struct block_device * bdev;
   const char *blkdev_name;
   fmode_t blkdev_mode;
} vblk_device_t;

typedef struct fio_request {
   struct completion comp; /* completion for sync IO */
   atomic_t   ref;     /* references */
   int    rw;          /* read/write */
   int    error;       /* bio error */
   int    bio_count;   /* count of bio's */
   void    *buf_ptr;
   uint64_t buf_size;
   uint32_t tag_id;
   struct bio *bio[0]; /* Attached bio's */
} fio_request_t; 

struct kthread_data {
   const char *name; /* kthread's name */
   vblk_device_t vblk_dev;
};

static struct kthread_data blk_thread;

struct task_struct *vblk_task;

int vdev_blk_fio_is_sync(fio_request_t *fr)
{
    return (fr->rw & REQ_SYNC);
}

void * kmem_alloc(size_t size, unsigned int __nocast flags)
{
    return kmalloc(size, flags);
}

void * kmem_zalloc(size_t size, unsigned int __nocast flags)
{
    void    *ptr;
    ptr = kmem_alloc(size, flags);
    if (ptr)
        memset((char *)ptr, 0, (int)size);
    return ptr;
}

void kmem_free(const void *ptr)
{
    kfree(ptr);
}

fio_request_t * vdev_blk_fio_alloc(int bio_count)
{
   fio_request_t * fr;
   int i;
   fr = kmem_zalloc(sizeof (fio_request_t) +
           sizeof (struct bio *) * bio_count, GFP_ATOMIC);
   if (fr) {
      init_completion(&fr->comp);
      atomic_set(&fr->ref, 0);
      fr->bio_count = bio_count;
      fr->error = 0;
      for (i=0; i<bio_count; i++)
          fr->bio[i] = NULL;
   }
   return fr;
}

void vdev_blk_fio_free(fio_request_t *fr)
{
     int i;
     for (i=0; i< fr->bio_count; i++)
     {
         if (fr->bio[i]) {
             printk(KERN_INFO "bio_put:%p\n", fr->bio[i]);
             bio_put(fr->bio[i]);
         }
     }
     printk(KERN_INFO "free fio_request fr:%p\n", fr);
     kmem_free(fr);
}

void vdev_blk_fio_get(fio_request_t *fr)
{
    printk(KERN_INFO "get fio_request fr:%p\n", fr);
    atomic_inc(&fr->ref);
}

int vdev_blk_fio_put(fio_request_t *fr)
{
    int rc;
    printk(KERN_INFO "put fio_request fr:%p\n", fr);
    rc = atomic_dec_return(&fr->ref);
    if (rc == 0) {
        vdev_blk_fio_free(fr);
    }
    return rc;
}

/* bio->bi_io_vec = bio->bi_inine_vecs[bio_nr_pages] */
static inline int bio_nr_pages(void *bio_ptr, unsigned int bio_size)
{
    unsigned long num = bio_size/(NUM_BIO_PER_REQUEST*SECTOR_SIZE);
    if( bio_size%SECTOR_SIZE ) return -EINVAL;
    if( 0 == num ) return -EINVAL;
    if( SECTOR_PER_BIO != num ) return -EINVAL;
    return num;
}

void vdev_blk_io_completion(struct bio *bio, int error)
{ 
  int rc, sts;
  fio_request_t *fr = (fio_request_t *)bio->bi_private;
  uint32_t tag_id = fr->tag_id % MAX_TAG;
  uint8_t tmp8 = 0xff;
  uint8_t *done;
  void *buf_ptr;
  uint64_t buf_size;
 
  BUG_ON(NULL == fr);

  /* save buf_ptr and size */
  buf_ptr = fr->buf_ptr;
  buf_size = fr->buf_size;

  if( (fr->rw&WRITE) == WRITE) { done = &wr_done[tag_id]; (*done)++; }
  else if ( (fr->rw&READ) == READ) { done = &rd_done[tag_id]; (*done)++; }
  else {  done = &tmp8; }

  printk(KERN_INFO "vdev_blk_io_completion:%p w:%d bio:%p error:%d page_addr:%p (%p, %llX) ref_cnt:%d bi_size:%d tagId:%d done:%X\n",
       fr, fr->rw, bio, error, page_address(bio_page(bio)), fr->buf_ptr, fr->buf_size, atomic_read(&bio->bi_cnt), bio->bi_size, tag_id, *done);

  if (bio->bi_size) return;

  if (fr->error == 0)
      fr->error = -error;

  rc = vdev_blk_fio_put(fr);

  printk(KERN_INFO "%s done:%d\n", __FUNCTION__, rc);

  if(rc == 1 && (fr->rw == READ)) {
    
	printk("tag:%d buf:%p size:%llX\n", tag_id, buf_ptr, buf_size);
    sts = lba_buf_comp(0xFACE0000+tag_id, buf_ptr, buf_size);
    status[tag_id] = sts;
    if(sts) {
	printk("tag:%d fail sts:%d\n", tag_id, sts);
	lba_buf_dump(tag_id, buf_ptr, 16);
    }
    else {
	printk("tag:%d pass sts:%d\n", tag_id, sts);
	lba_buf_dump(tag_id, buf_ptr, 8);
    }
  }

  if ( (rc == 1) && vdev_blk_fio_is_sync(fr) ) {
      printk(KERN_INFO "%s sync done:%d\n", __FUNCTION__, rc);
      complete(&fr->comp);
  }
  return;
}

int vdev_blk_io(struct vblk_device *vblkdev,  uint32_t tag_id, void *buf_ptr, size_t buf_size, int flags)
{
 int i, v;
 int error = 0;
 int bio_count = NUM_BIO_PER_REQUEST;
 gfp_t gfp_mask = GFP_NOIO;
 int nr_pages;
 fio_request_t * fr;
 struct bio * bio;
 int bio_size;
 void *bio_ptr;
 struct bio_vec *bv;

 fr = vdev_blk_fio_alloc(bio_count);
 if (NULL == fr) {
  return ENOMEM;
 }

 printk("req: tag:%d rw:%d buf:%p %lX\n", tag_id, flags, buf_ptr, buf_size);

 fr->tag_id  = tag_id; 
 fr->buf_ptr = buf_ptr;
 fr->buf_size = buf_size;
 fr->rw = flags;
 bio_ptr    = buf_ptr;
 bio_size   = buf_size;

 nr_pages = bio_nr_pages(bio_ptr, bio_size);
 if(nr_pages <= 0) {
	return 0;
 }

 for (i = 0; i< fr->bio_count; i++) {

  bio = bio_kmalloc(gfp_mask, nr_pages);

  if (NULL == bio) {
    vdev_blk_fio_free(fr);
    return ENOMEM;
  }

  vdev_blk_fio_get(fr);

  bio->bi_bdev    = vblkdev->bdev;
  bio->bi_rw      = flags;
  bio->bi_end_io  = vdev_blk_io_completion;
  bio->bi_private = fr; 
  bio->bi_idx     = 0;
  bio->bi_vcnt    = nr_pages;
  bio->bi_sector  = i*nr_pages*8 + tag_id*nr_pages*bio_count*8; /* Count in 512B unit => x8 */
  bio->bi_size    = SECTOR_SIZE*nr_pages;
  bio->bi_seg_front_size = SECTOR_SIZE;
  bio->bi_seg_back_size = SECTOR_SIZE;

  bio_for_each_segment(bv, bio, v) {
    bio_ptr       = buf_ptr + SECTOR_SIZE*v + i*SECTOR_SIZE*nr_pages;
    if( kmem_virt(bio_ptr) ) {
       bv->bv_page   = vmalloc_to_page(bio_ptr);
    } else {
       bv->bv_page   = virt_to_page(bio_ptr);
    }
    bv->bv_len    = SECTOR_SIZE;
    bv->bv_offset = 0;
  }

  fr->bio[i] =  bio;
 }

 vdev_blk_fio_get(fr);

 for (i = 0; i < fr->bio_count; i++) {
  struct bio * bio = fr->bio[i];
  if (bio) {
   printk(KERN_INFO "submit_bio:%p tag:%d rw:%d bio%d:%p buf_ptr:%p ref:%d\n",
       fr, tag_id, fr->rw, i, bio, buf_ptr + i*SECTOR_SIZE*nr_pages,
       atomic_read(&bio->bi_cnt));

   submit_bio(bio->bi_rw,  bio);
  }
 }

 if (vdev_blk_fio_is_sync(fr) ) {
  wait_for_completion(&fr->comp);
        printk(KERN_INFO "%s wait sync completion done:%d\n",
   __FUNCTION__, fr->error);
  error = fr->error;
 }

 (void) vdev_blk_fio_put(fr);

 return error;
}

void vdev_blk_open(vblk_device_t *vblkdev)
{
 vblkdev->blkdev_name = "/dev/sbulla";
 vblkdev->blkdev_mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;
 vblkdev->bdev = my_blkdev_get_by_path(vblkdev->blkdev_name,
                 vblkdev->blkdev_mode, vblkdev);

 BUG_ON( NULL == vblkdev->bdev );

 cache_mem = kmalloc_array( CACHE_MEM_SIZE, SECTOR_SIZE, GFP_KERNEL);
 BUG_ON( NULL == cache_mem );

 //ref: http://www.makelinux.net/books/lkd2/ch11lev1sec5
 v_mem = vmalloc( CACHE_MEM_SIZE * SECTOR_SIZE );
 BUG_ON( NULL == v_mem );
}

void vdev_blk_close(vblk_device_t *vblkdev)
{
 my_blkdev_close(vblkdev->bdev, vblkdev->blkdev_mode);
 kfree(cache_mem);
 vfree(v_mem);
}

/* Test both buffers from vmalloc and kmalloc 
 */
uint8_t * vdev_blk_get_buf(uint32_t idx)
{
 BUG_ON( NULL == cache_mem );
 if(idx&1) {
   idx>>=1;
 return &cache_mem[idx*SECTOR_SIZE];
 } else {
   idx>>=1;
 return &v_mem[idx*SECTOR_SIZE];
 }
}


#define ST_WRITE 0
#define ST_POLL  1
#define ST_READ  2
#define ST_DONE  3
/*
 * the kernel thread
 */
int kthread_function(void *data)
{
 struct kthread_data *pdata = (struct kthread_data*)data;
 void * buf_ptr;
 size_t buf_size;
 uint32_t state = ST_WRITE;
 int flags = READ;
 int tag = 0;
 int i,cnt;
 printk("Vmalloc: start:%p end:%p\n", (void*)VMALLOC_START, (void*) VMALLOC_END);
 for(i=0; i<MAX_TAG; i++) {
    wr_done[i] = rd_done[i] = status[i] = 0;
 }

  buf_size = SECTOR_SIZE * SECTOR_PER_BIO * NUM_BIO_PER_REQUEST;

 while(1) {
  if (kthread_should_stop())
   break;
   msleep(10);


   /* Write max tag data */
   if( (state == ST_WRITE) || (state == ST_READ)) {
      if(tag < MAX_TAG) {

      flags = (state == ST_WRITE) ? WRITE : READ;

      buf_ptr = vdev_blk_get_buf(tag);
      if(flags==WRITE) lba_buf_fill(0xFACE0000+tag, buf_ptr, buf_size);
      else lba_buf_fill(0xBAD00000+tag, buf_ptr, buf_size);
	printk("issue io: tag:%d rw:%d\n", tag, flags);
      vdev_blk_io(&pdata->vblk_dev,  tag, buf_ptr, buf_size, flags);

      tag++;
      }
      else {
	if(state == ST_WRITE) {
	state = ST_POLL;
	} else {
	state = ST_DONE;
	}
      }
   }
   /* wait for write done */
   else if (state == ST_POLL) {
     cnt = 0;
     for(i=0; i<MAX_TAG; i++) {
     	if(wr_done[i]==NUM_BIO_PER_REQUEST) {
		cnt++;
     	}
     }
     if(cnt == MAX_TAG) {
         state = ST_READ;
	 tag  =0;
     }
  }
 }

 return 0;
}

int __init kthread_init(void)
{
 vdev_blk_open(&blk_thread.vblk_dev);
 blk_thread.name = "blk_thread";
 printk(KERN_INFO "%s init_module() called\n", blk_thread.name);
 vblk_task = kthread_run(kthread_function, &blk_thread, "kvblk");
 return 0;
}


void __exit kthread_exit(void)
{
 int i, cnt=0;
 for(i=0; i<MAX_TAG; i++) {
     	if(status[i] == 0) {
		cnt++;
     	}
 }
 if(cnt == MAX_TAG)  {
     printk(KERN_INFO "\n ==> %d/%d Test Passed.\n", cnt, MAX_TAG);
 }
else {
     printk(KERN_INFO "\n ==> %d/%d Test Fail.\n", cnt, MAX_TAG);
}
 printk(KERN_INFO "%s cleanup_module() called\n", blk_thread.name);
 kthread_stop(vblk_task); /* stop kthread first */
 vdev_blk_close(&blk_thread.vblk_dev); /* clean up at the end */
}


int lba_buf_zero(void* buf, int sz)
{
	int i;
	uint64_t* p = (uint64_t*)buf;
	sz >>= 3;
	for(i=0; i<sz; i++) {
		p[i] = 0;
	}
	return 0;
}

int lba_buf_fill(uint64_t seed, void* buf, int sz)
{
	int i;
	uint64_t chksum=0;
	uint64_t* p = (uint64_t*)buf;
	sz >>= 3;
	for(i=0; i<sz; i++) {
		p[i] = ((seed<<32) + i);
		chksum += p[i];
	}
	return chksum;
}

int lba_buf_comp(uint64_t seed, void* buf, int sz)
{
	int i, rc=0;
	uint64_t chksum=0;
	uint64_t* p = (uint64_t*)buf;
	sz >>= 3;
	for(i=0; i<sz; i++) {
		if(p[i] != ((seed<<32) + i)) rc++;
		chksum += p[i];
	}
	return rc;
}

int lba_buf_dump(uint64_t lba, void* buf, int sz)
{
	int rc = 0;
	int i;
	uint64_t* p = (uint64_t*)buf;
	if(!sz)
	{
		return rc;
	}
	printk("\n\n===lba:%llX buf:%p sz:%d\n", lba, buf, sz);
	sz >>= 3;
	for(i=0; i<sz; i++) {
		if(i%4==0) printk("\n");
		printk("%016llX ", p[i]);
	}
	return rc;
}


module_init(kthread_init);
module_exit(kthread_exit);
