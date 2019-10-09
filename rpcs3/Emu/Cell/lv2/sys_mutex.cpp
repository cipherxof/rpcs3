#include "stdafx.h"
#include "sys_mutex.h"

#include "Emu/System.h"
#include "Emu/IdManager.h"
#include "Emu/IPC.h"

#include "Emu/Cell/ErrorCodes.h"
#include "Emu/Cell/PPUThread.h"

LOG_CHANNEL(sys_mutex);

template<> DECLARE(ipc_manager<lv2_mutex, u64>::g_ipc) {};

error_code sys_mutex_create(ppu_thread& ppu, vm::ptr<u32> mutex_id, vm::ptr<sys_mutex_attribute_t> attr)
{
	vm::temporary_unlock(ppu);

	sys_mutex.warning("sys_mutex_create(mutex_id=*0x%x, attr=*0x%x)", mutex_id, attr);

	if (!mutex_id || !attr)
	{
		return CELL_EFAULT;
	}

	switch (attr->protocol)
	{
	case SYS_SYNC_FIFO: break;
	case SYS_SYNC_PRIORITY: break;
	case SYS_SYNC_PRIORITY_INHERIT:
		sys_mutex.warning("sys_mutex_create(): SYS_SYNC_PRIORITY_INHERIT");
		break;
	default:
	{
		sys_mutex.error("sys_mutex_create(): unknown protocol (0x%x)", attr->protocol);
		return CELL_EINVAL;
	}
	}

	switch (attr->recursive)
	{
	case SYS_SYNC_RECURSIVE: break;
	case SYS_SYNC_NOT_RECURSIVE: break;
	default:
	{
		sys_mutex.error("sys_mutex_create(): unknown recursive (0x%x)", attr->recursive);
		return CELL_EINVAL;
	}
	}

	if (attr->adaptive != SYS_SYNC_NOT_ADAPTIVE)
	{
		sys_mutex.todo("sys_mutex_create(): unexpected adaptive (0x%x)", attr->adaptive);
	}

	if (auto error = lv2_obj::create<lv2_mutex>(attr->pshared, attr->ipc_key, attr->flags, [&]()
	{
		return std::make_shared<lv2_mutex>(
			attr->protocol,
			attr->recursive,
			attr->pshared,
			attr->adaptive,
			attr->ipc_key,
			attr->flags,
			attr->name_u64);
	}))
	{
		return error;
	}

	*mutex_id = idm::last_id();
	if (*mutex_id == 0x85016400 || *mutex_id == 0x85016c00 || *mutex_id == 0x85016a00)
	{
		sys_mutex.error("HACK sys_mutex_created (mutex_id=0x%x, p: %u r: 0x%x pshared: 0x%x ipc: 0x%x flags: 0x%x name: 0x%x)@0x%x in thread %s",
			*mutex_id, attr->protocol, attr->recursive, attr->pshared, attr->ipc_key, attr->flags, attr->name_u64, ppu.lr, ppu.get_name().c_str());
		{
			// Determine stack range
			u32 stack_ptr = static_cast<u32>(ppu.gpr[1]);
			u32 stack_min = stack_ptr & ~0xfff;
			u32 stack_max = stack_min + 4096;

			while (stack_min && vm::check_addr(stack_min - 4096, 4096, vm::page_writable))
				stack_min -= 4096;

			while (stack_max + 4096 && vm::check_addr(stack_max, 4096, vm::page_writable))
				stack_max += 4096;

			for (u64 sp = vm::read64(stack_ptr); sp >= stack_min && std::max(sp, sp + 0x200) < stack_max; sp = vm::read64(static_cast<u32>(sp)))
				sys_mutex.error("\t> from 0x%08llx (0x0)\n", vm::read64(static_cast<u32>(sp + 16)));
		}
	}

	return CELL_OK;
}

error_code sys_mutex_destroy(ppu_thread& ppu, u32 mutex_id)
{
	vm::temporary_unlock(ppu);

	sys_mutex.warning("sys_mutex_destroy(mutex_id=0x%x)", mutex_id);

	const auto mutex = idm::withdraw<lv2_obj, lv2_mutex>(mutex_id, [](lv2_mutex& mutex) -> CellError
	{
		std::lock_guard lock(mutex.mutex);

		if (mutex.owner || mutex.lock_count)
		{
			return CELL_EBUSY;
		}

		if (mutex.cond_count)
		{
			return CELL_EPERM;
		}

		return {};
	});

	if (!mutex)
	{
		return CELL_ESRCH;
	}

	if (mutex.ret)
	{
		return mutex.ret;
	}

	return CELL_OK;
}

error_code sys_mutex_lock(ppu_thread& ppu, u32 mutex_id, u64 timeout)
{
	vm::temporary_unlock(ppu);

	sys_mutex.trace("sys_mutex_lock(mutex_id=0x%x, timeout=0x%llx)", mutex_id, timeout);

	bool fake_timeout = false;
	bool wanted_mutex = false;
	if (mutex_id == 0x85016400 || mutex_id == 0x85016c00 || mutex_id == 0x85016a00)
	{
		wanted_mutex = true;
		if (timeout == 0)
		{
			//timeout      = 250000;
			//fake_timeout = true;
		}
		else
			sys_mutex.error("HACK NOTICE sys_mutex_lock(mutex_id=0x%x)@0x%x in thread %s timeout is %llu", mutex_id, ppu.lr, ppu.get_name().c_str(), timeout);
	}

	u32 prev_wanted_mutex = 0;
	u64 returnPC = 0;
	if (wanted_mutex)
	{
		prev_wanted_mutex = ppu.last_mutex_wanted.exchange(mutex_id);
		{
			// Determine stack range
			u32 stack_ptr = static_cast<u32>(ppu.gpr[1]);
			u32 stack_min = stack_ptr & ~0xfff;
			u32 stack_max = stack_min + 4096;

			while (stack_min && vm::check_addr(stack_min - 4096, 4096, vm::page_writable))
				stack_min -= 4096;

			while (stack_max + 4096 && vm::check_addr(stack_max, 4096, vm::page_writable))
				stack_max += 4096;

			for (u64 sp = vm::read64(stack_ptr); sp >= stack_min && std::max(sp, sp + 0x200) < stack_max; sp = vm::read64(static_cast<u32>(sp)))
			{
				returnPC = vm::read64(static_cast<u32>(sp + 16));
				break;
			}
		}
	}

	const auto mutex = idm::get<lv2_obj, lv2_mutex>(mutex_id, [&](lv2_mutex& mutex)
	{
		CellError result = mutex.try_lock(ppu.id);

		if (result == CELL_EBUSY)
		{
			std::lock_guard lock(mutex.mutex);

			if (mutex.try_own(ppu, ppu.id))
			{
				result = {};
			}
			else
			{
				mutex.sleep(ppu, timeout);
			}
		}

		return result;
	});

	if (!mutex)
	{
		sys_mutex.error("FAIL sys_mutex_lock(mutex_id=0x%x)@0x%x in thread %s returning CELL_ESRCH", mutex_id, ppu.lr, ppu.get_name().c_str());
		if (wanted_mutex)
			ppu.last_mutex_wanted.compare_exchange(mutex_id, prev_wanted_mutex);

		return CELL_ESRCH;
	}

	if (mutex.ret)
	{
		if (mutex.ret != CELL_EBUSY)
		{
			if (mutex.ret == CELL_EDEADLK)
				sys_mutex.error("FAIL sys_mutex_lock(mutex_id=0x%x)@0x%x in thread %s returning CELL_EDEADLCK", mutex_id, ppu.lr, ppu.get_name().c_str());

			return mutex.ret;
		}
	}
	else
	{
		if (wanted_mutex)
		{
			ppu.last_mutex_acquired.exchange(mutex_id);
			ppu.last_acquired_mutex_pc = returnPC;
			ppu.last_mutex_wanted.compare_exchange(mutex_id, 0);
		}

		return CELL_OK;
	}

	ppu.gpr[3] = CELL_OK;
	const auto start_time = get_system_time();
	while (!ppu.state.test_and_reset(cpu_flag::signal))
	{
		if (ppu.is_stopped())
		{
			return 0;
		}

		if (timeout)
		{
			if (lv2_obj::wait_timeout(timeout, &ppu))
			{
				std::lock_guard lock(mutex->mutex);

				if (!mutex->unqueue(mutex->sq, &ppu))
				{
					timeout = 0;
					continue;
				}

				ppu.gpr[3] = CELL_ETIMEDOUT;
				if (fake_timeout)
				{
					const auto owner      = mutex->owner.load();      // Owner Thread ID
					const auto lock_count = mutex->lock_count.load(); // Recursive Locks
					const auto cond_count = mutex->cond_count.load(); // Condition Variables

					sys_mutex.error("HACK sys_mutex_lock(mutex_id=0x%x)@0x%x in thread %s returning CELL_OK because %llu us has passed (o: 0x%x b: %u l: %u c: %u)",
						mutex_id, ppu.lr, ppu.get_name().c_str(), get_system_time() - start_time, owner >> 1, owner & 1, lock_count, cond_count);
					for (auto waitIt = mutex->sq.cbegin(), end = mutex->sq.cend(); waitIt != end; waitIt++)
					{
						cpu_thread* thrd = *waitIt;
						sys_mutex.error("\twaiting thread name: %s", thrd->get_name().c_str());
					}
					{
						// Determine stack range
						u32 stack_ptr = static_cast<u32>(ppu.gpr[1]);
						u32 stack_min = stack_ptr & ~0xfff;
						u32 stack_max = stack_min + 4096;

						while (stack_min && vm::check_addr(stack_min - 4096, 4096, vm::page_writable))
							stack_min -= 4096;

						while (stack_max + 4096 && vm::check_addr(stack_max, 4096, vm::page_writable))
							stack_max += 4096;

						for (u64 sp = vm::read64(stack_ptr); sp >= stack_min && std::max(sp, sp + 0x200) < stack_max; sp = vm::read64(static_cast<u32>(sp)))
							sys_mutex.error("\t> from 0x%08llx (0x0)\n", vm::read64(static_cast<u32>(sp + 16)));
					}
					mutex->owner.store((ppu.id << 1) | (owner&1));
					ppu.gpr[3] = CELL_OK;
				}
				break;
			}
		}
		else
		{
			thread_ctrl::wait();
		}
	}

	if (ppu.gpr[3] == CELL_OK && wanted_mutex)
	{
		ppu.last_mutex_acquired.exchange(mutex_id);
		ppu.last_acquired_mutex_pc = returnPC;
		ppu.last_mutex_wanted.compare_exchange(mutex_id, 0);
	}

	return not_an_error(ppu.gpr[3]);
}

error_code sys_mutex_trylock(ppu_thread& ppu, u32 mutex_id)
{
	vm::temporary_unlock(ppu);

	sys_mutex.trace("sys_mutex_trylock(mutex_id=0x%x)", mutex_id);

	if (mutex_id == 0x85016400 || mutex_id == 0x85016c00 || mutex_id == 0x85016a00)
	{
		sys_mutex.error("HACK NOTICE sys_mutex_trylock(mutex_id=0x%x)@0x%x in thread %s attempted!", mutex_id, ppu.lr, ppu.get_name().c_str());
	}

	const auto mutex = idm::check<lv2_obj, lv2_mutex>(mutex_id, [&](lv2_mutex& mutex)
	{
		return mutex.try_lock(ppu.id);
	});

	if (!mutex)
	{
		sys_mutex.error("FAIL sys_mutex_trylock(mutex_id=0x%x)@0x%x in thread %s returning CELL_ESRCH", mutex_id, ppu.lr, ppu.get_name().c_str());
		return CELL_ESRCH;
	}

	if (mutex.ret)
	{
		if (mutex.ret == CELL_EBUSY)
		{
			return not_an_error(CELL_EBUSY);
		}

		return mutex.ret;
	}

	return CELL_OK;
}

error_code sys_mutex_unlock(ppu_thread& ppu, u32 mutex_id)
{
	vm::temporary_unlock(ppu);

	sys_mutex.trace("sys_mutex_unlock(mutex_id=0x%x)", mutex_id);



	u32 origOwner = 0;
	const auto mutex = idm::check<lv2_obj, lv2_mutex>(mutex_id, [&](lv2_mutex& mutex)
	{
		return mutex.try_unlock(ppu.id, &origOwner);
	});

	if (!mutex)
	{
		sys_mutex.error("FAIL sys_mutex_unlock(mutex_id=0x%x)@0x%x in thread %s returning CELL_ESRCH", mutex_id, ppu.lr, ppu.get_name().c_str());
		return CELL_ESRCH;
	}

	if (mutex.ret == CELL_EBUSY)
	{
		std::lock_guard lock(mutex->mutex);

		if (auto cpu = mutex->reown<ppu_thread>())
		{
			mutex->awake(cpu);
		}
	}
	else if (mutex.ret)
	{
		if (mutex.ret == CELL_EPERM)
		{
			sys_mutex.error("FAIL sys_mutex_unlock(mutex_id=0x%x)@0x%x in thread %s returning CELL_EPERM origOwner: 0x%x b: %u",
				mutex_id, ppu.lr, ppu.get_name().c_str(), origOwner >> 1, origOwner & 1);
		}

		return mutex.ret;
	}

	ppu.last_mutex_acquired.compare_exchange(mutex_id, 0);
	return CELL_OK;
}
