#include "stdafx.h"
#include "sys_timer.h"

#include "Emu/System.h"
#include "Emu/IdManager.h"

#include "Emu/Cell/ErrorCodes.h"
#include "Emu/Cell/PPUThread.h"
#include "sys_event.h"
#include "sys_process.h"
#include "sys_mutex.h"

#include <thread>

LOG_CHANNEL(sys_timer);

extern u64 get_guest_system_time();

void lv2_timer_context::operator()()
{
	while (!Emu.IsStopped())
	{
		const u32 _state = state;

		if (_state == SYS_TIMER_STATE_RUN)
		{
			const u64 _now = get_guest_system_time();
			const u64 next = expire;

			if (_now >= next)
			{
				std::lock_guard lock(mutex);

				if (const auto queue = port.lock())
				{
					queue->send(source, data1, data2, next);
				}

				if (period)
				{
					// Set next expiration time and check again (HACK)
					expire += period;
					continue;
				}

				// Stop after oneshot
				state.compare_and_swap_test(SYS_TIMER_STATE_RUN, SYS_TIMER_STATE_STOP);
				continue;
			}

			// TODO: use single global dedicated thread for busy waiting, no timer threads
			lv2_obj::wait_timeout(next - _now);
		}
		else if (_state == SYS_TIMER_STATE_STOP)
		{
			thread_ctrl::wait_for(10000);
		}
		else
		{
			break;
		}
	}
}

void lv2_timer_context::on_abort()
{
	// Signal thread using invalid state
	state = -1;
}

error_code sys_timer_create(ppu_thread& ppu, vm::ptr<u32> timer_id)
{
	vm::temporary_unlock(ppu);

	sys_timer.warning("sys_timer_create(timer_id=*0x%x)", timer_id);

	if (const u32 id = idm::make<lv2_obj, lv2_timer>("Timer Thread"))
	{
		*timer_id = id;
		return CELL_OK;
	}

	return CELL_EAGAIN;
}

error_code sys_timer_destroy(ppu_thread& ppu, u32 timer_id)
{
	vm::temporary_unlock(ppu);

	sys_timer.warning("sys_timer_destroy(timer_id=0x%x)", timer_id);

	const auto timer = idm::withdraw<lv2_obj, lv2_timer>(timer_id, [&](lv2_timer& timer) -> CellError
	{
		std::lock_guard lock(timer.mutex);

		if (!timer.port.expired())
		{
			return CELL_EISCONN;
		}

		return {};
	});

	if (!timer)
	{
		return CELL_ESRCH;
	}

	if (timer.ret)
	{
		return timer.ret;
	}

	return CELL_OK;
}

error_code sys_timer_get_information(ppu_thread& ppu, u32 timer_id, vm::ptr<sys_timer_information_t> info)
{
	vm::temporary_unlock(ppu);

	sys_timer.trace("sys_timer_get_information(timer_id=0x%x, info=*0x%x)", timer_id, info);

	const auto timer = idm::check<lv2_obj, lv2_timer>(timer_id, [&](lv2_timer& timer)
	{
		std::lock_guard lock(timer.mutex);

		info->next_expire = timer.expire;
		info->period      = timer.period;
		info->timer_state = timer.state;
	});

	if (!timer)
	{
		return CELL_ESRCH;
	}

	return CELL_OK;
}

error_code _sys_timer_start(ppu_thread& ppu, u32 timer_id, u64 base_time, u64 period)
{
	vm::temporary_unlock(ppu);

	sys_timer.trace("_sys_timer_start(timer_id=0x%x, base_time=0x%llx, period=0x%llx)", timer_id, base_time, period);

	const u64 start_time = get_guest_system_time();

	if (!period && start_time >= base_time)
	{
		// Invalid oneshot (TODO: what will happen if both args are 0?)
		return not_an_error(CELL_ETIMEDOUT);
	}

	if (period && period < 100)
	{
		// Invalid periodic timer
		return CELL_EINVAL;
	}

	const auto timer = idm::check<lv2_obj, lv2_timer>(timer_id, [&](lv2_timer& timer) -> CellError
	{
		std::unique_lock lock(timer.mutex);

		if (timer.state != SYS_TIMER_STATE_STOP)
		{
			return CELL_EBUSY;
		}

		if (timer.port.expired())
		{
			return CELL_ENOTCONN;
		}

		// sys_timer_start_periodic() will use current time (TODO: is it correct?)
		timer.expire = base_time ? base_time : start_time + period;
		timer.period = period;
		timer.state  = SYS_TIMER_STATE_RUN;

		lock.unlock();
		thread_ctrl::notify(timer);
		return {};
	});

	if (!timer)
	{
		return CELL_ESRCH;
	}

	if (timer.ret)
	{
		return timer.ret;
	}

	return CELL_OK;
}

error_code sys_timer_stop(ppu_thread& ppu, u32 timer_id)
{
	vm::temporary_unlock(ppu);

	sys_timer.trace("sys_timer_stop()");

	const auto timer = idm::check<lv2_obj, lv2_timer>(timer_id, [](lv2_timer& timer)
	{
		std::lock_guard lock(timer.mutex);

		timer.state = SYS_TIMER_STATE_STOP;
	});

	if (!timer)
	{
		return CELL_ESRCH;
	}

	return CELL_OK;
}

error_code sys_timer_connect_event_queue(ppu_thread& ppu, u32 timer_id, u32 queue_id, u64 name, u64 data1, u64 data2)
{
	vm::temporary_unlock(ppu);

	sys_timer.warning("sys_timer_connect_event_queue(timer_id=0x%x, queue_id=0x%x, name=0x%llx, data1=0x%llx, data2=0x%llx)", timer_id, queue_id, name, data1, data2);

	const auto timer = idm::check<lv2_obj, lv2_timer>(timer_id, [&](lv2_timer& timer) -> CellError
	{
		const auto found = idm::find_unlocked<lv2_obj, lv2_event_queue>(queue_id);

		if (!found)
		{
			return CELL_ESRCH;
		}

		std::lock_guard lock(timer.mutex);

		if (!timer.port.expired())
		{
			return CELL_EISCONN;
		}

		// Connect event queue
		timer.port   = std::static_pointer_cast<lv2_event_queue>(found->second);
		timer.source = name ? name : ((u64)process_getpid() << 32) | timer_id;
		timer.data1  = data1;
		timer.data2  = data2;
		return {};
	});

	if (!timer)
	{
		return CELL_ESRCH;
	}

	if (timer.ret)
	{
		return timer.ret;
	}

	return CELL_OK;
}

error_code sys_timer_disconnect_event_queue(ppu_thread& ppu, u32 timer_id)
{
	vm::temporary_unlock(ppu);

	sys_timer.warning("sys_timer_disconnect_event_queue(timer_id=0x%x)", timer_id);

	const auto timer = idm::check<lv2_obj, lv2_timer>(timer_id, [](lv2_timer& timer) -> CellError
	{
		std::lock_guard lock(timer.mutex);

		if (timer.port.expired())
		{
			return CELL_ENOTCONN;
		}

		timer.state = SYS_TIMER_STATE_STOP;
		timer.port.reset();
		return {};
	});

	if (!timer)
	{
		return CELL_ESRCH;
	}

	if (timer.ret)
	{
		return timer.ret;
	}

	return CELL_OK;
}

error_code sys_timer_sleep(ppu_thread& ppu, u32 sleep_time)
{
	vm::temporary_unlock(ppu);

	sys_timer.trace("sys_timer_sleep(sleep_time=%d) -> sys_timer_usleep()", sleep_time);

	return sys_timer_usleep(ppu, sleep_time * u64{1000000});
}

error_code sys_timer_usleep(ppu_thread& ppu, u64 sleep_time)
{
	vm::temporary_unlock(ppu);

	static u64 successfulUrgentSpurs = 0;
	sys_timer.trace("sys_timer_usleep(sleep_time=0x%llx)", sleep_time);

	u32 unlocked_mutex_ids[3] = { 0, 0, 0 };
	if (sleep_time == 5467)
	{
		successfulUrgentSpurs++;
		return CELL_OK;
	}

	if (sleep_time == 160 && u32(ppu.gpr[31]) == 0x80410A0Au) //Audio_Control thread failed to cellSpursAddUrgentCommand
	{
		static const u32 interest_mutex_ids[3] = { 0x85016400, 0x85016c00, 0x85016a00 };

		size_t unlocked_mut_num = 0;
		for (const u32 queried_mutex_id : interest_mutex_ids)
		{
			auto curr_mutex = idm::get<lv2_obj, lv2_mutex>(queried_mutex_id);
			if (!curr_mutex)
				continue;

			const auto owner = curr_mutex->owner.load();
			if ((owner>>1) == ppu.id)
			{
				const auto unlock_err = sys_mutex_unlock(ppu, queried_mutex_id);
				if (unlock_err)
					sys_timer.error("sys_timer_usleep failed to unlock mutex 0x%x with err 0x%x", queried_mutex_id, unlock_err.value);
				else
					unlocked_mutex_ids[unlocked_mut_num++] = queried_mutex_id;
			}
		}

		if (unlocked_mut_num > 0)
		{
			sys_timer.error("HACK sys_timer_usleep in Audio Control thread unlocking mutex_1 0x%x mutex_2 0x%x mutex_3 0x%x succ: %llu",
				unlocked_mutex_ids[0], unlocked_mutex_ids[1], unlocked_mutex_ids[2], successfulUrgentSpurs);
		}
	}

	if (sleep_time)
	{
		lv2_obj::sleep(ppu, sleep_time);

		lv2_obj::wait_timeout<true>(sleep_time);

		if (ppu.is_stopped())
		{
			return 0;
		}
	}
	else
	{
		std::this_thread::yield();
	}

	for (size_t i=3; i>0; i--)
	{
		const u32 curr_mut_id = unlocked_mutex_ids[i-1];
		if (curr_mut_id == 0)
			continue;

		const auto lock_err = sys_mutex_lock(ppu, curr_mut_id, 0);
		if (lock_err)
			sys_timer.error("sys_timer_usleep failed to relock mutex_%u 0x%x with err 0x%x", u32(i), curr_mut_id, lock_err.value);
	}
	return CELL_OK;
}
