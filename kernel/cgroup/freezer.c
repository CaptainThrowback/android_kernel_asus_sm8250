/*
 * cgroup_freezer.c -  control group freezer subsystem
 *
 * Copyright IBM Corporation, 2007
 *
 * Author : Cedric Le Goater <clg@fr.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <linux/export.h>
#include <linux/slab.h>
#include <linux/cgroup.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/freezer.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>
//#include <sys/time.h>
#include <linux/delay.h>

/*
 * A cgroup is freezing if any FREEZING flags are set.  FREEZING_SELF is
 * set if "FROZEN" is written to freezer.state cgroupfs file, and cleared
 * for "THAWED".  FREEZING_PARENT is set if the parent freezer is FREEZING
 * for whatever reason.  IOW, a cgroup has FREEZING_PARENT set if one of
 * its ancestors has FREEZING_SELF set.
 */
enum freezer_state_flags {
	CGROUP_FREEZER_ONLINE	= (1 << 0), /* freezer is fully online */
	CGROUP_FREEZING_SELF	= (1 << 1), /* this freezer is freezing */
	CGROUP_FREEZING_PARENT	= (1 << 2), /* the parent freezer is freezing */
	CGROUP_FROZEN		= (1 << 3), /* this and its descendants frozen */

	/* mask for all FREEZING flags */
	CGROUP_FREEZING		= CGROUP_FREEZING_SELF | CGROUP_FREEZING_PARENT,
};

#ifndef CONFIG_CGF_NOTIFY_EVENT
struct freezer {
	struct cgroup_subsys_state	css;
	unsigned int			state;
};
#endif

static DEFINE_MUTEX(freezer_mutex);

static inline struct freezer *css_freezer(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct freezer, css) : NULL;
}

static inline struct freezer *task_freezer(struct task_struct *task)
{
	return css_freezer(task_css(task, freezer_cgrp_id));
}

static struct freezer *parent_freezer(struct freezer *freezer)
{
	return css_freezer(freezer->css.parent);
}

bool cgroup_freezing(struct task_struct *task)
{
	bool ret;

	rcu_read_lock();
	ret = task_freezer(task)->state & CGROUP_FREEZING;
	rcu_read_unlock();

	return ret;
}

static const char *freezer_state_strs(unsigned int state)
{
	if (state & CGROUP_FROZEN)
		return "FROZEN";
	if (state & CGROUP_FREEZING)
		return "FREEZING";
	return "THAWED";
};
//#define CONFIG_CGF_NOTIFY_EVENT
#ifdef CONFIG_CGF_NOTIFY_EVENT
#define UNFREEZE_MAX_RETRY_COUNT 20
#define UNFREEZE_RETRY_DELAY_MS 10
#define UNFREEZE_MAX_TASK_RETRY_COUNT 0
#define UNFREEZE_MAX_RETRY_TIMEOUT_US 2000000
static void *s_unqueue_tasks[MAX_UNQUEUE_TASK_SIZE];
static int s_utsk_index = 0;
static struct workqueue_struct *cgf_notify_wq = NULL;
static int s_not_queued_count = 0;
static int s_seq_id = 0;
int unfreeze_task(struct freezer *freezer ,struct task_struct *t,int is_retry,int is_unqueue,int seq_id) {
	int ret = 0;
	int skip_not_freeze = 0;
	int is_frozen = 0;
	int is_freezing = 0;
	int is_frozen_done = 0;
	int is_freezing_done = 0;
	int do_again_count= 0;
	int is_frozen_count = 0;
	int is_freezing_count = 0;
	int retry_err_count =0;

	if (!t || t==NULL) {
		printk(KERN_ERR"[CGF]seq_id=%d, %s, task null\n",seq_id, __func__);
		goto out_task_null;
	}
	//	printk(KERN_ERR"[CGF] %s, start: pid: %d,  frozen %d, freezing %d\n", __func__, t->pid, frozen(t), freezing(t));
		is_frozen = frozen(t) ;
		is_freezing = freezing(t);
		if (is_frozen || is_freezing){
		    ret = cgf_attach_task_group(freezer->css.cgroup, t->pid);
		    is_frozen_done = frozen(t) ;
		    is_freezing_done = freezing(t);
		    for (do_again_count=0;do_again_count<UNFREEZE_MAX_TASK_RETRY_COUNT;do_again_count++) {
		    	if (is_frozen_done || is_freezing_done) {
		    		// do again
		    		ret = cgf_attach_task_group(freezer->css.cgroup, t->pid);
		    		is_frozen_done = frozen(t) ;
		    		is_freezing_done = freezing(t);
		    		is_frozen_count+=is_frozen_done;
		    		is_freezing_count+=is_freezing_done;
		    		if (ret!=0) {
		    			retry_err_count++;
		    		}
		    	} else {
		    		break;
		    	}
		    }
		} else {
			ret = 1;
			skip_not_freeze = 1;
		}
		if (is_frozen_done || is_freezing_done) {
			ret = 0;
		} else {
			ret =1;
		}
		if (skip_not_freeze == 0) {
			printk(KERN_ERR"[CGF]seq_id=%d, %s,  return: %d, pid: %d skip:%d is_frozen:%d->%d(%d) , is_freezing:%d->%d(%d) , do_again_count:%d,err_count:%d,is_retry:%d,is_unqueue:%d\n",
					seq_id,__func__, ret, t->pid,skip_not_freeze,
					is_frozen,is_frozen_done,is_frozen_count,
					is_freezing,is_freezing_done,is_freezing_count,
					do_again_count,retry_err_count,
					is_retry,is_unqueue);
		}
		return ret;

out_task_null:
		return 1;
}

static void cgf_event_work(struct work_struct *work)
{
	struct freezer *freezer = container_of(work, struct freezer, cgf_notify_work);
	struct task_struct *t;
	struct task_struct *unqueue_t;
	int main_task_pass = 0;
	int i=0;
	int unqueue_task_pass = 0;
	int main_task_fail_count = 1;// 1 for first run
	int unqueue_task_fail_count = 1;// 1 for first run
	int retry_count = 0;
//	int max_retry_count = 200;
//	struct timeval t0, t1;
   unsigned long delta_usec = 0;
//	gettimeofday(&t0, NULL);
   int seq_id = 99999;
	for (retry_count=0;retry_count<UNFREEZE_MAX_RETRY_COUNT;retry_count++) {
		if (main_task_fail_count) {
			main_task_fail_count = 0;
			// main task_struct
			if(freezer->event.data && freezer->event.data != NULL) {
				t = freezer->event.data;
				seq_id = freezer->event.seq_id;
				main_task_pass = unfreeze_task(freezer,t,0,0,seq_id);
				if (main_task_pass) {
					 freezer->event.data = NULL;
				} else {
					main_task_fail_count++;
				}
			}
		}
		if (unqueue_task_fail_count) {
			unqueue_task_fail_count = 0;
			//printk(KERN_ERR"[CGF]seq_id=%d, %s, v2 unqueue_tasks_size:%d\n", seq_id,__func__, freezer->event.unqueue_tasks_size);
			// unqueue task struct
			for (i=0;i<freezer->event.unqueue_tasks_size;i++) {
				unqueue_t = freezer->event.unqueue_tasks[i];
				if (unqueue_t && unqueue_t != NULL) {
					unqueue_task_pass = unfreeze_task(freezer,unqueue_t,0,1,seq_id);
					if (unqueue_task_pass) {
						freezer->event.unqueue_tasks[i] = NULL;
					} else {
						unqueue_task_fail_count++;
					}
				}
			}
		}
		if (unqueue_task_fail_count==0 && main_task_fail_count==0) {
			break;
		} else{
//			gettimeofday(&t1, NULL);
//			delta_usec = (t1.tv_sec - t0.tv_sec) * 1000000 + t1.tv_usec - t0.tv_usec;
			//printk(KERN_ERR"[CGF]seq_id=%d,  %s, delay retry_count:%d unqueue_task_fail_count:%d, main_task_fail_count:%d,delta_usec:%lu\n",seq_id, __func__,retry_count,unqueue_task_fail_count,main_task_fail_count,delta_usec);
			if (delta_usec > UNFREEZE_MAX_RETRY_TIMEOUT_US) {
				break;
			}
			mdelay(UNFREEZE_RETRY_DELAY_MS);
			// TODO try msleep
		}

	}
//	gettimeofday(&t1, NULL);
//	delta_usec = (t1.tv_sec - t0.tv_sec) * 1000000 + t1.tv_usec - t0.tv_usec;
	// TODO need remove this log
	if (retry_count>0) {
		printk(KERN_ERR"[CGF]seq_id=%d, %s, final retry_count:%d unqueue_task_fail_count:%d, main_task_fail_count:%d,delta_usec:%lu\n",seq_id, __func__,retry_count,unqueue_task_fail_count,main_task_fail_count,delta_usec);
	}

	// unqueued task struct
//out_failed:
//
//	if(ret == -EINVAL)
//	   printk(KERN_ERR"[CGF] %s, Attaching an invalid group code: %d\n", __func__, ret);
	 
}

static int cgf_event_notify(struct notifier_block *self,
			      unsigned long action, void *data)
{
    struct freezer *freezer = container_of(self, struct freezer, nf);
	struct cgf_event *event;
	struct task_struct *t=NULL;
	struct task_struct *t_unqueue_task=NULL;
	int ret = -EPERM;
	int i;
	int skip_duplicate_task = 0;
	event = data;
	if(event == NULL || event->data == NULL){
		ret = -EINVAL;
		goto out_invalid_data;
	}

	t = event->data;
	
	if (!frozen(t) && !freezing(t)){
		ret = -EINVAL;
		goto out_invalid_data;
	}

    if(cgf_notify_wq) {
        ret = queue_work(cgf_notify_wq, &freezer->cgf_notify_work);
    	// update event
        if (ret != 0) {
        	freezer->event.info = event->info;
        	freezer->event.data = event->data;

        	// get array
        	freezer->event.unqueue_tasks_size = s_utsk_index;
        	for (i=0;i<MAX_UNQUEUE_TASK_SIZE;i++) {
        		freezer->event.unqueue_tasks[i] = s_unqueue_tasks[i];
        	}
        	// set seq id
        	freezer->event.seq_id = s_seq_id;
        	s_seq_id++;
        	if (s_seq_id > 10000) {
        		s_seq_id = 0;
        	}
        	// reset unqueue task array
        	if (s_not_queued_count > 0 ) {
        		printk(KERN_ERR"[CGF]seq_id=%d , %s, s_not_queued_count:%d,s_utsk_index: %d\n",freezer->event.seq_id, __func__,s_not_queued_count,s_utsk_index);
        		s_not_queued_count = 0;
        	}
        	printk(KERN_ERR"[CGF]seq_id=%d , %s, enqueue: %d, pid:%d, type:%d s_utsk_index:%d\n",freezer->event.seq_id, __func__, ret, t->pid, event->type,s_utsk_index);
        	s_utsk_index = 0;
        } else {
        	// init array
        	if (s_utsk_index ==0) {
            	for (i=0;i<MAX_UNQUEUE_TASK_SIZE;i++) {
            		s_unqueue_tasks[i] = NULL;
            	}
        	}
        	// add data to array
        	if (s_utsk_index < MAX_UNQUEUE_TASK_SIZE) {
        		skip_duplicate_task = 0;
        		for (i=0;i<s_utsk_index;i++) {
        			t_unqueue_task = s_unqueue_tasks[i];
        			if (t_unqueue_task && (t_unqueue_task->pid == t->pid) ){
        				// skip duplicate task
        				skip_duplicate_task = 1;
        				break;
        			}
        		}
        		if (skip_duplicate_task==0) {
        			s_unqueue_tasks[s_utsk_index] = t;
        			s_utsk_index ++;
        		}
        	} else {
        		s_not_queued_count++;
        	}
        }
    }

    // TODO need remove this log
	//printk(KERN_ERR"[CGF] %s, skip_duplicate_task:%d,invalid_data: %d, pid:%d, type:%d s_utsk_index:%d\n", __func__,skip_duplicate_task, ret, t->pid, event->type,s_utsk_index);
	
	if (ret)
		return 0;
out_invalid_data:

//    printk(KERN_ERR"[CGF] %s, invalid_data2: %d, pid: %d\n", __func__, ret, t->pid);
	return 0;
}

static struct notifier_block cgf_event_notifier = {
	.notifier_call	= cgf_event_notify,
};
#endif


static struct cgroup_subsys_state *
freezer_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct freezer *freezer;

	freezer = kzalloc(sizeof(struct freezer), GFP_KERNEL);
	if (!freezer)
		return ERR_PTR(-ENOMEM);

	return &freezer->css;
}

/**
 * freezer_css_online - commit creation of a freezer css
 * @css: css being created
 *
 * We're committing to creation of @css.  Mark it online and inherit
 * parent's freezing state while holding both parent's and our
 * freezer->lock.
 */
static int freezer_css_online(struct cgroup_subsys_state *css)
{
	struct freezer *freezer = css_freezer(css);
	struct freezer *parent = parent_freezer(freezer);

	mutex_lock(&freezer_mutex);

	freezer->state |= CGROUP_FREEZER_ONLINE;

	if (parent && (parent->state & CGROUP_FREEZING)) {
		freezer->state |= CGROUP_FREEZING_PARENT | CGROUP_FROZEN;
		atomic_inc(&system_freezing_cnt);
	}
#ifdef CONFIG_CGF_NOTIFY_EVENT
		if (!strcmp(css->ss->name, FREEZER_SS_NAME)
			&& !strcmp(css->cgroup->kn->name, FREEZER_KN_NAME) ) {
			if(freezer->cgf_notify_work.func == NULL) {
				INIT_WORK(&freezer->cgf_notify_work, cgf_event_work);
				printk(KERN_DEBUG"[CGF] %s, cgf_notify_work initialized for %s\n",
					__func__, FREEZER_SS_NAME);
			}
			if(freezer->nf.notifier_call == NULL) {
				memcpy(&freezer->nf,  &cgf_event_notifier, sizeof(struct notifier_block));
				cgf_register_notifier(&freezer ->nf);
				printk(KERN_DEBUG"[CGF] %s, cgf_event_notifier registered for %s\n",
					__func__, css->cgroup->kn->name);
	    	}
		}
		spin_lock_init(&freezer->lock);
#endif

	mutex_unlock(&freezer_mutex);
	return 0;
}

/**
 * freezer_css_offline - initiate destruction of a freezer css
 * @css: css being destroyed
 *
 * @css is going away.  Mark it dead and decrement system_freezing_count if
 * it was holding one.
 */
static void freezer_css_offline(struct cgroup_subsys_state *css)
{
	struct freezer *freezer = css_freezer(css);

	mutex_lock(&freezer_mutex);

	if (freezer->state & CGROUP_FREEZING)
		atomic_dec(&system_freezing_cnt);

	freezer->state = 0;
#ifdef CONFIG_CGF_NOTIFY_EVENT
	
		if(freezer->nf.notifier_call)
			cgf_unregister_notifier(&freezer->nf);
		if(freezer->cgf_notify_work.func)
			cancel_work_sync(&freezer->cgf_notify_work);
		if(cgf_notify_wq) {
			destroy_workqueue(cgf_notify_wq);
			cgf_notify_wq = NULL;
		}
#endif

	mutex_unlock(&freezer_mutex);
}

static void freezer_css_free(struct cgroup_subsys_state *css)
{
	kfree(css_freezer(css));
}

/*
 * Tasks can be migrated into a different freezer anytime regardless of its
 * current state.  freezer_attach() is responsible for making new tasks
 * conform to the current state.
 *
 * Freezer state changes and task migration are synchronized via
 * @freezer->lock.  freezer_attach() makes the new tasks conform to the
 * current state and all following state changes can see the new tasks.
 */
static void freezer_attach(struct cgroup_taskset *tset)
{
	struct task_struct *task;
	struct cgroup_subsys_state *new_css;

	mutex_lock(&freezer_mutex);

	/*
	 * Make the new tasks conform to the current state of @new_css.
	 * For simplicity, when migrating any task to a FROZEN cgroup, we
	 * revert it to FREEZING and let update_if_frozen() determine the
	 * correct state later.
	 *
	 * Tasks in @tset are on @new_css but may not conform to its
	 * current state before executing the following - !frozen tasks may
	 * be visible in a FROZEN cgroup and frozen tasks in a THAWED one.
	 */
	cgroup_taskset_for_each(task, new_css, tset) {
		struct freezer *freezer = css_freezer(new_css);

		if (!(freezer->state & CGROUP_FREEZING)) {
			__thaw_task(task);
		} else {
			freeze_task(task);
			/* clear FROZEN and propagate upwards */
			while (freezer && (freezer->state & CGROUP_FROZEN)) {
				freezer->state &= ~CGROUP_FROZEN;
				freezer = parent_freezer(freezer);
			}
		}
	}

	mutex_unlock(&freezer_mutex);
}

/**
 * freezer_fork - cgroup post fork callback
 * @task: a task which has just been forked
 *
 * @task has just been created and should conform to the current state of
 * the cgroup_freezer it belongs to.  This function may race against
 * freezer_attach().  Losing to freezer_attach() means that we don't have
 * to do anything as freezer_attach() will put @task into the appropriate
 * state.
 */
static void freezer_fork(struct task_struct *task)
{
	struct freezer *freezer;

	/*
	 * The root cgroup is non-freezable, so we can skip locking the
	 * freezer.  This is safe regardless of race with task migration.
	 * If we didn't race or won, skipping is obviously the right thing
	 * to do.  If we lost and root is the new cgroup, noop is still the
	 * right thing to do.
	 */
	if (task_css_is_root(task, freezer_cgrp_id))
		return;

	mutex_lock(&freezer_mutex);
	rcu_read_lock();

	freezer = task_freezer(task);
	if (freezer->state & CGROUP_FREEZING)
		freeze_task(task);

	rcu_read_unlock();
	mutex_unlock(&freezer_mutex);
}

/**
 * update_if_frozen - update whether a cgroup finished freezing
 * @css: css of interest
 *
 * Once FREEZING is initiated, transition to FROZEN is lazily updated by
 * calling this function.  If the current state is FREEZING but not FROZEN,
 * this function checks whether all tasks of this cgroup and the descendant
 * cgroups finished freezing and, if so, sets FROZEN.
 *
 * The caller is responsible for grabbing RCU read lock and calling
 * update_if_frozen() on all descendants prior to invoking this function.
 *
 * Task states and freezer state might disagree while tasks are being
 * migrated into or out of @css, so we can't verify task states against
 * @freezer state here.  See freezer_attach() for details.
 */
static void update_if_frozen(struct cgroup_subsys_state *css)
{
	struct freezer *freezer = css_freezer(css);
	struct cgroup_subsys_state *pos;
	struct css_task_iter it;
	struct task_struct *task;

	lockdep_assert_held(&freezer_mutex);

	if (!(freezer->state & CGROUP_FREEZING) ||
	    (freezer->state & CGROUP_FROZEN))
		return;

	/* are all (live) children frozen? */
	rcu_read_lock();
	css_for_each_child(pos, css) {
		struct freezer *child = css_freezer(pos);

		if ((child->state & CGROUP_FREEZER_ONLINE) &&
		    !(child->state & CGROUP_FROZEN)) {
			rcu_read_unlock();
			return;
		}
	}
	rcu_read_unlock();

	/* are all tasks frozen? */
	css_task_iter_start(css, 0, &it);

	while ((task = css_task_iter_next(&it))) {
		if (freezing(task)) {
			/*
			 * freezer_should_skip() indicates that the task
			 * should be skipped when determining freezing
			 * completion.  Consider it frozen in addition to
			 * the usual frozen condition.
			 */
			if (!frozen(task) && !freezer_should_skip(task))
				goto out_iter_end;
		}
	}

	freezer->state |= CGROUP_FROZEN;
out_iter_end:
	css_task_iter_end(&it);
}

static int freezer_read(struct seq_file *m, void *v)
{
	struct cgroup_subsys_state *css = seq_css(m), *pos;

	mutex_lock(&freezer_mutex);
	rcu_read_lock();

	/* update states bottom-up */
	css_for_each_descendant_post(pos, css) {
		if (!css_tryget_online(pos))
			continue;
		rcu_read_unlock();

		update_if_frozen(pos);

		rcu_read_lock();
		css_put(pos);
	}

	rcu_read_unlock();
	mutex_unlock(&freezer_mutex);

	seq_puts(m, freezer_state_strs(css_freezer(css)->state));
	seq_putc(m, '\n');
	return 0;
}

static void freeze_cgroup(struct freezer *freezer)
{
	struct css_task_iter it;
	struct task_struct *task;

	css_task_iter_start(&freezer->css, 0, &it);
	while ((task = css_task_iter_next(&it)))
		freeze_task(task);
	css_task_iter_end(&it);
}

static void unfreeze_cgroup(struct freezer *freezer)
{
	struct css_task_iter it;
	struct task_struct *task;

	css_task_iter_start(&freezer->css, 0, &it);
	while ((task = css_task_iter_next(&it)))
		__thaw_task(task);
	css_task_iter_end(&it);
}

/**
 * freezer_apply_state - apply state change to a single cgroup_freezer
 * @freezer: freezer to apply state change to
 * @freeze: whether to freeze or unfreeze
 * @state: CGROUP_FREEZING_* flag to set or clear
 *
 * Set or clear @state on @cgroup according to @freeze, and perform
 * freezing or thawing as necessary.
 */
static void freezer_apply_state(struct freezer *freezer, bool freeze,
				unsigned int state)
{
	/* also synchronizes against task migration, see freezer_attach() */
	lockdep_assert_held(&freezer_mutex);

	if (!(freezer->state & CGROUP_FREEZER_ONLINE))
		return;

	if (freeze) {
		if (!(freezer->state & CGROUP_FREEZING))
			atomic_inc(&system_freezing_cnt);
		freezer->state |= state;
		freeze_cgroup(freezer);
	} else {
		bool was_freezing = freezer->state & CGROUP_FREEZING;

		freezer->state &= ~state;

		if (!(freezer->state & CGROUP_FREEZING)) {
			if (was_freezing)
				atomic_dec(&system_freezing_cnt);
			freezer->state &= ~CGROUP_FROZEN;
			unfreeze_cgroup(freezer);
		}
	}
}

/**
 * freezer_change_state - change the freezing state of a cgroup_freezer
 * @freezer: freezer of interest
 * @freeze: whether to freeze or thaw
 *
 * Freeze or thaw @freezer according to @freeze.  The operations are
 * recursive - all descendants of @freezer will be affected.
 */
static void freezer_change_state(struct freezer *freezer, bool freeze)
{
	struct cgroup_subsys_state *pos;

	/*
	 * Update all its descendants in pre-order traversal.  Each
	 * descendant will try to inherit its parent's FREEZING state as
	 * CGROUP_FREEZING_PARENT.
	 */
	mutex_lock(&freezer_mutex);
	rcu_read_lock();
	css_for_each_descendant_pre(pos, &freezer->css) {
		struct freezer *pos_f = css_freezer(pos);
		struct freezer *parent = parent_freezer(pos_f);

		if (!css_tryget_online(pos))
			continue;
		rcu_read_unlock();

		if (pos_f == freezer)
			freezer_apply_state(pos_f, freeze,
					    CGROUP_FREEZING_SELF);
		else
			freezer_apply_state(pos_f,
					    parent->state & CGROUP_FREEZING,
					    CGROUP_FREEZING_PARENT);

		rcu_read_lock();
		css_put(pos);
	}
	rcu_read_unlock();
	mutex_unlock(&freezer_mutex);
}

static ssize_t freezer_write(struct kernfs_open_file *of,
			     char *buf, size_t nbytes, loff_t off)
{
	bool freeze;

	buf = strstrip(buf);

	if (strcmp(buf, freezer_state_strs(0)) == 0)
		freeze = false;
	else if (strcmp(buf, freezer_state_strs(CGROUP_FROZEN)) == 0)
#ifdef CONFIG_CGF_NOTIFY_EVENT
			{
				/* only create workqueue for bg freezer cgroup */
				struct cgroup *cgroup = of->kn->parent->priv;
		
				if (!strcmp(cgroup->kn->name, FREEZER_BG_KN_NAME)
					&& !cgf_notify_wq) {
				   cgf_notify_wq = create_singlethread_workqueue("cgf_bg_wq");
				}
					
		freeze = true;
	}
#else
		freeze = true;
#endif	
	else
		return -EINVAL;

	freezer_change_state(css_freezer(of_css(of)), freeze);
	return nbytes;
}

static u64 freezer_self_freezing_read(struct cgroup_subsys_state *css,
				      struct cftype *cft)
{
	struct freezer *freezer = css_freezer(css);

	return (bool)(freezer->state & CGROUP_FREEZING_SELF);
}

static u64 freezer_parent_freezing_read(struct cgroup_subsys_state *css,
					struct cftype *cft)
{
	struct freezer *freezer = css_freezer(css);

	return (bool)(freezer->state & CGROUP_FREEZING_PARENT);
}

static struct cftype files[] = {
	{
		.name = "state",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = freezer_read,
		.write = freezer_write,
	},
	{
		.name = "self_freezing",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_u64 = freezer_self_freezing_read,
	},
	{
		.name = "parent_freezing",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_u64 = freezer_parent_freezing_read,
	},
	{ }	/* terminate */
};

struct cgroup_subsys freezer_cgrp_subsys = {
	.css_alloc	= freezer_css_alloc,
	.css_online	= freezer_css_online,
	.css_offline	= freezer_css_offline,
	.css_free	= freezer_css_free,
	.attach		= freezer_attach,
	.fork		= freezer_fork,
	.legacy_cftypes	= files,
};
