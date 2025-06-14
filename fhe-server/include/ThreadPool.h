#pragma once
#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <vector>
#include <thread>
#include <queue>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <stdexcept>

class ThreadPool {
public:
    ThreadPool(size_t num_threads);
    
    // Template function can be implemented in the header or in a separate .tpp file.
    template<class F>
    void submit(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if(stop_pool)
                throw std::runtime_error("submit on stopped ThreadPool");
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }

    ~ThreadPool();

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::atomic<bool> stop_pool;
};

#endif // THREAD_POOL_H
