/* Copyright (c) 2011-2013, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <kgsl_device.h>

#include "kgsl_trace.h"
#include "adreno.h"

static struct kmem_cache *events_cache;

static inline void signal_event(struct kgsl_device *device,
		struct kgsl_event *event, int result)
{
	list_del(&event->node);
	event->result = result;
	queue_work(device->events_wq, &event->work);
}

static void _kgsl_event_worker(struct work_struct *work)
{
	struct kgsl_event *event = container_of(work, struct kgsl_event, work);
	int id = KGSL_CONTEXT_ID(event->context);

	trace_kgsl_fire_event(id, event->timestamp, event->result, jiffies - event->created,
		event->func);

	if (event->func)
		event->func(event->device, event->context, event->priv, event->result);

	kgsl_context_put(event->context);
	kmem_cache_free(events_cache, event);
}

void kgsl_process_event_group(struct kgsl_device *device,
		struct kgsl_event_group *group)
{
	struct kgsl_event *event, *tmp;
	unsigned int timestamp;
	struct kgsl_context *context;

	if (group == NULL)
		return;

	context = group->context;

	_kgsl_context_get(context);

	spin_lock(&group->lock);

	timestamp = kgsl_readtimestamp(device, context, KGSL_TIMESTAMP_RETIRED);

	if (timestamp_cmp(timestamp, group->processed) <= 0)
		goto out;

	list_for_each_entry_safe(event, tmp, &group->events, node) {
		if (timestamp_cmp(event->timestamp, timestamp) <= 0)
			signal_event(device, event, KGSL_EVENT_RETIRED);
	}

	group->processed = timestamp;

out:
	spin_unlock(&group->lock);
	kgsl_context_put(context);
}
EXPORT_SYMBOL(kgsl_process_event_group);

void kgsl_cancel_events_timestamp(struct kgsl_device *device,
		struct kgsl_event_group *group, unsigned int timestamp)
{
	struct kgsl_event *event, *tmp;

	spin_lock(&group->lock);

	list_for_each_entry_safe(event, tmp, &group->events, node) {
		if (timestamp_cmp(timestamp, event->timestamp) == 0)
			signal_event(device, event, KGSL_EVENT_CANCELLED);
	}

	spin_unlock(&group->lock);
}
EXPORT_SYMBOL(kgsl_cancel_events_timestamp);

void kgsl_cancel_events(struct kgsl_device *device,
		struct kgsl_event_group *group)
{
	struct kgsl_event *event, *tmp;

	spin_lock(&group->lock);

	list_for_each_entry_safe(event, tmp, &group->events, node)
		signal_event(device, event, KGSL_EVENT_CANCELLED);

	spin_unlock(&group->lock);
}
EXPORT_SYMBOL(kgsl_cancel_events);

void kgsl_cancel_event(struct kgsl_device *device,
		struct kgsl_event_group *group, unsigned int timestamp,
		kgsl_event_func func, void *priv)
{
	struct kgsl_event *event, *tmp;
	spin_lock(&group->lock);

	list_for_each_entry_safe(event, tmp, &group->events, node) {
		if (timestamp == event->timestamp && func == event->func &&
			event->priv == priv)
			signal_event(device, event, KGSL_EVENT_CANCELLED);
	}

	spin_unlock(&group->lock);
}
EXPORT_SYMBOL(kgsl_cancel_event);

int kgsl_add_event(struct kgsl_device *device, struct kgsl_event_group *group,
		unsigned int timestamp, kgsl_event_func func, void *priv)
{
	unsigned int queued, retired;
	struct kgsl_context *context = group->context;
	struct kgsl_event *event;

	if (!func)
		return -EINVAL;

	if (!context || !(context->flags & KGSL_CONTEXT_USER_GENERATED_TS)) {
		queued = kgsl_readtimestamp(device, context, KGSL_TIMESTAMP_QUEUED);
		if (timestamp_cmp(timestamp, queued) > 0)
			return -EINVAL;
	}

	event = kmem_cache_alloc(events_cache, GFP_KERNEL);
	if (event == NULL)
		return -ENOMEM;

	
	_kgsl_context_get(context);

	event->device = device;
	event->context = context;
	event->timestamp = timestamp;
	event->priv = priv;
	event->func = func;
	event->created = jiffies;

	INIT_WORK(&event->work, _kgsl_event_worker);

	trace_kgsl_register_event(KGSL_CONTEXT_ID(context), timestamp, func);

	spin_lock(&group->lock);

	retired = kgsl_readtimestamp(device, context, KGSL_TIMESTAMP_RETIRED);

	if (timestamp_cmp(retired, timestamp) >= 0) {
		event->result = KGSL_EVENT_RETIRED;
		queue_work(device->events_wq, &event->work);
		spin_unlock(&group->lock);
		return 0;
	}

	
	list_add_tail(&event->node, &group->events);

	spin_unlock(&group->lock);

	return 0;
}
EXPORT_SYMBOL(kgsl_add_event);

static DEFINE_RWLOCK(group_lock);
static LIST_HEAD(group_list);

void kgsl_process_events(struct work_struct *work)
{
	struct kgsl_event_group *group;
	struct kgsl_device *device = container_of(work, struct kgsl_device,
		event_work);

	read_lock(&group_lock);
	list_for_each_entry(group, &group_list, group)
		kgsl_process_event_group(device, group);
	read_unlock(&group_lock);
}
EXPORT_SYMBOL(kgsl_process_events);

void kgsl_del_event_group(struct kgsl_event_group *group)
{
	
	BUG_ON(!list_empty(&group->events));

	write_lock(&group_lock);
	list_del(&group->group);
	write_unlock(&group_lock);
}
EXPORT_SYMBOL(kgsl_del_event_group);

void kgsl_add_event_group(struct kgsl_event_group *group,
		struct kgsl_context *context)
{
	spin_lock_init(&group->lock);
	INIT_LIST_HEAD(&group->events);

	group->context = context;

	write_lock(&group_lock);
	list_add_tail(&group->group, &group_list);
	write_unlock(&group_lock);
}
EXPORT_SYMBOL(kgsl_add_event_group);

void kgsl_events_exit(void)
{
	if (events_cache)
		kmem_cache_destroy(events_cache);
}

void __init kgsl_events_init(void)
{
	events_cache = KMEM_CACHE(kgsl_event, 0);
}
