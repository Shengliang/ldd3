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

/** @brief sector size */
#define SECTOR_SIZE 4096 
#define SECTOR_PER_BIO 4
#define NUM_BIO_PER_REQUEST 2

/** @brief cache memory array */
uint8_t * cache_mem;

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
static inline unsigned long bio_nr_pages(void *bio_ptr, unsigned int bio_size)
{
    unsigned long num = bio_size/(NUM_BIO_PER_REQUEST*SECTOR_SIZE);
    BUG_ON( bio_size%SECTOR_SIZE );
    BUG_ON( 0 == num );
    BUG_ON( SECTOR_PER_BIO != num );
    return num;
}

void vdev_blk_io_completion(struct bio *bio, int error)
{
  int rc;
  fio_request_t *fr = bio->bi_private;

  BUG_ON(NULL == fr);

  printk(KERN_INFO "vdev_blk_io_completion:%p bio:%p error:%d page_addr:%p"
      " vec(%p, %d %d) ref_cnt:%d\n",
       fr, bio, error, page_address(bio_page(bio)),
  bio->bi_io_vec[0].bv_page,
  bio->bi_io_vec[0].bv_len,
  bio->bi_io_vec[0].bv_offset,
            atomic_read(&bio->bi_cnt));

  if (bio->bi_size) return;

  if (fr->error == 0)
      fr->error = -error;

  rc = vdev_blk_fio_put(fr);

  printk(KERN_INFO "%s done:%d\n", __FUNCTION__, rc);

  if ( (rc == 1) && vdev_blk_fio_is_sync(fr) ) {
      printk(KERN_INFO "%s sync done:%d\n", __FUNCTION__, rc);
      complete(&fr->comp);
  }
  return;
}

int vdev_blk_io(struct vblk_device *vblkdev,  void *buf_ptr,
		size_t buf_size, uint64_t buf_offset, int flags)
{
 int i, v;
 int error = 0;
 int bio_count = NUM_BIO_PER_REQUEST;
 gfp_t gfp_mask = GFP_NOIO;
 int nr_pages;
 fio_request_t * fr;
 struct bio * bio;
 int bio_size;
 uint64_t bio_offset;
 void *bio_ptr;
 struct bio_vec *bv;

 fr = vdev_blk_fio_alloc(bio_count);
 if (NULL == fr) {
  return ENOMEM;
 }

 fr->rw = flags;
 bio_ptr    = buf_ptr;
 bio_offset = buf_offset;
 bio_size   = buf_size;

 nr_pages = bio_nr_pages(bio_ptr, bio_size);

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
  bio->bi_sector  = 0;
  bio->bi_size    = SECTOR_SIZE*nr_pages;
  bio->bi_seg_front_size = SECTOR_SIZE;
  bio->bi_seg_back_size = SECTOR_SIZE;

  bio_for_each_segment(bv, bio, v) {
   bv->bv_page   = virt_to_page(bio_ptr + bio_offset +
     SECTOR_SIZE*v + i*SECTOR_SIZE*nr_pages);
   bv->bv_len    = SECTOR_SIZE;
   bv->bv_offset = 0;
  }

  fr->bio[i] =  bio;
 }

 vdev_blk_fio_get(fr);

 for (i = 0; i < fr->bio_count; i++) {
  struct bio * bio = fr->bio[i];
  if (bio) {
   printk(KERN_INFO "submit_bio:%p bio:%p buf_ptr:%p ref:%d\n",
       fr, bio, buf_ptr + i*SECTOR_SIZE*nr_pages,
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

 cache_mem = kmalloc_array( 256, SECTOR_SIZE, GFP_KERNEL);
 BUG_ON( NULL == cache_mem );
}

void vdev_blk_close(vblk_device_t *vblkdev)
{
 my_blkdev_close(vblkdev->bdev, vblkdev->blkdev_mode);
 kfree(cache_mem);
}

uint8_t * vdev_blk_get_buf(uint32_t idx)
{
 BUG_ON( NULL == cache_mem );
 idx &= (CACHE_MEM_SIZE-1);
 return &cache_mem[idx*SECTOR_SIZE];
}

/*
 * the kernel thread
 */
int kthread_function(void *data)
{
 struct kthread_data *pdata = (struct kthread_data*)data;
 void * buf_ptr;
 size_t buf_size;
 uint64_t buf_offset;
 //int flags = READ_SYNC;
 int flags = READ;
 int cnt = 0;

 while(1) {
  if (kthread_should_stop())
   break;
  msleep(10);

  buf_size = SECTOR_SIZE * SECTOR_PER_BIO * NUM_BIO_PER_REQUEST;
  buf_ptr = vdev_blk_get_buf(4);
  buf_offset = 0;

  if(cnt==0) {
   vdev_blk_io(&pdata->vblk_dev,  buf_ptr, buf_size,
    buf_offset, flags);
  }
  cnt++;

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
 printk(KERN_INFO "%s cleanup_module() called\n", blk_thread.name);
 kthread_stop(vblk_task); /* stop kthread first */
 vdev_blk_close(&blk_thread.vblk_dev); /* clean up at the end */
}

module_init(kthread_init);
module_exit(kthread_exit);
