#pragma once
#ifndef __singleton_h__
#define __singleton_h__

#if (defined _WIN32 || defined _WIN64)
#   include <windows.h>
#endif

#include "mutex.h"

template<typename T>
class singleton
{
public:
    static inline T* GetInstance()
	{
		if (instance_ == 0)
		{
			lock_.lock();
			if (instance_ == 0)
			{
				instance_ = new T;
			}
			lock_.unlock();
		}
		return instance_;
	}

    static inline void FreeInstance()
    {
        free_ = true;
        lock_.lock();
		if (instance_ != 0)
		{
			delete instance_;
			instance_ = 0;
		}
        lock_.unlock();
    }

protected:
    singleton() {}
    virtual ~singleton()
    {
        if (!free_)
        {
            lock_.lock();
			if (instance_ != 0)
			{
				delete instance_;
				instance_ = 0;
			}
            lock_.unlock();
        }
    }
private:
    singleton(const singleton&) {}
    singleton& operator=(const singleton&) {}

private:
	static T* instance_;
    static mutex lock_;
    static bool free_;
};

template<typename T>
T* singleton<T>::instance_ = NULL;

template<typename T>
mutex singleton<T>::lock_;

template<typename T>
bool singleton<T>::free_ = false;

#endif // __singleton_h__
