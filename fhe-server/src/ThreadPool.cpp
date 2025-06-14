#include "ThreadPool.h"
#include "Utils.h"
#include <iostream>

ThreadPool::ThreadPool(size_t num_threads) : stop_pool(false) {
    for (size_t i = 0; i < num_threads; ++i) {
        workers.emplace_back([this, i] {
            auto tid_ss = get_tid_ss();
            std::cout << "[POOL_WORKER " << i << " TID " << tid_ss.str() << "] Started." << std::endl;
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(this->queue_mutex);
                    this->condition.wait(lock, [this]{ return this->stop_pool || !this->tasks.empty(); });
                    if(this->stop_pool && this->tasks.empty())
                        return;
                    task = std::move(this->tasks.front());
                    this->tasks.pop();
                }
                task();
            }
        });
    }
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        stop_pool = true;
    }
    condition.notify_all();
    for(auto &worker : workers) {
        if(worker.joinable())
            worker.join();
    }
}
