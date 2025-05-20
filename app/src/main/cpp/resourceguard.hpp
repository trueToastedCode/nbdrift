#pragma once

#include <iostream>
#include <tuple>
#include <utility>
#include <stdexcept>
#include <type_traits>
#include <optional>

/**
 * @namespace resourceguard
 * @brief Provides RAII (Resource Acquisition Is Initialization) utilities for managing resources
 * 
 * This namespace contains the ResourceGuard class template which implements the RAII idiom
 * for automatic resource cleanup. It handles multiple resources of different types simultaneously
 * and provides safe resource management with customizable deletion policies.
 */
namespace resourceguard {

    /**
     * @brief Default trait for validity checking of resources
     * 
     * This template defines how to determine if a resource is valid. The default
     * implementation considers all resources valid.
     * 
     * @tparam T The resource type to check
     */
    template<typename T>
    struct ValidityCheck {
        /**
         * @brief Checks if a resource is valid
         * @param resource The resource to check
         * @return Always returns true for base case
         */
        static bool check(const T&) { return true; }
    };

    /**
     * @brief Specialization for pointer types
     * 
     * Considers a pointer valid if it's not null.
     * 
     * @tparam T The pointed-to type
     */
    template<typename T>
    struct ValidityCheck<T*> {
        /**
         * @brief Checks if a pointer is valid (non-null)
         * @param p The pointer to check
         * @return true if pointer is not null, false otherwise
         */
        static bool check(T* p) { return p != nullptr; }
    };

    /**
     * @brief Specialization for pointer references
     * 
     * Considers a pointer reference valid if it's not null.
     * 
     * @tparam T The pointed-to type
     */
    template<typename T>
    struct ValidityCheck<T* const&> {
        /**
         * @brief Checks if a pointer reference is valid (non-null)
         * @param p The pointer reference to check
         * @return true if pointer is not null, false otherwise
         */
        static bool check(T* const& p) { return p != nullptr; }
    };

    /**
     * @class ResourceGuard
     * @brief RAII wrapper for managing one or more resources
     * 
     * ResourceGuard is a class template that manages the lifecycle of one or more resources.
     * It ensures resources are properly cleaned up when the ResourceGuard instance goes out of scope
     * or is explicitly released. The class supports move semantics but prevents copying to ensure
     * clear ownership of resources.
     * 
     * @tparam Deleter A callable type that handles resource cleanup
     * @tparam Resources The types of resources to manage
     */
    template<typename Deleter, typename... Resources>
    class ResourceGuard {
        std::tuple<Resources...> m_resources;  ///< Tuple containing the managed resources
        Deleter m_deleter;                     ///< Function object for resource cleanup
        bool m_released = false;               ///< Flag indicating if resources have been released

        /**
         * @brief Cleans up resources if they haven't been released yet
         * 
         * Applies the deleter to the resources and marks them as released.
         * Errors during cleanup are logged to stderr but don't propagate.
         */
        void cleanup() noexcept {
            if (!m_released) {
                // try {
                //     std::apply(m_deleter, m_resources);
                // } catch (...) {
                //     std::cerr << "Cleanup error - potential leak" << std::endl;
                // }
                std::apply(m_deleter, m_resources);
                m_resources = {};
                m_released = true;
            }
        }

    public:
        /**
         * @brief Constructs a ResourceGuard with the specified deleter and resources
         * 
         * @tparam D Deleter type (deduced)
         * @tparam Args Resource types (deduced)
         * @param deleter The cleanup function to call when resources are released
         * @param args The resources to manage
         */
        template<typename D, typename... Args>
        explicit ResourceGuard(D&& deleter, Args&&... args)
            : m_deleter(std::forward<D>(deleter)),
              m_resources(std::forward<Args>(args)...) {}

        /**
         * @brief Destructor, automatically cleans up resources if not already released
         */
        ~ResourceGuard() { cleanup(); }

        /**
         * @brief Move constructor
         * 
         * Transfers ownership of resources from another ResourceGuard
         * 
         * @param other The ResourceGuard to move from
         */
         ResourceGuard(ResourceGuard&& other) noexcept
            : m_resources(std::move(other.m_resources)),
              m_deleter(std::move(other.m_deleter)),
              m_released(other.m_released) {
            other.m_released = true;
        }

        /**
         * @brief Move assignment operator
         * 
         * Transfers ownership of resources from another ResourceGuard,
         * cleaning up any resources this instance currently owns
         * 
         * @param other The ResourceGuard to move from
         * @return Reference to this instance
         */
         ResourceGuard& operator=(ResourceGuard&& other) noexcept {
            if (this != &other) {
                cleanup();
                m_resources = std::move(other.m_resources);
                m_deleter = std::move(other.m_deleter);
                m_released = other.m_released;
                other.m_released = true;
            }
            return *this;
        }
        
        // /**
        //  * @brief Accesses the first resource
        //  * 
        //  * @return Reference to the first resource
        //  * @throws std::logic_error if resources have been released
        //  */
        // decltype(auto) get() const {
        //     if (m_released) throw std::logic_error("Resource released");
        //     return std::get<0>(m_resources);
        // }

        // /**
        //  * @brief Accesses a specific resource by index
        //  * 
        //  * @tparam I The index of the resource to access
        //  * @return Reference to the specified resource
        //  * @throws std::logic_error if resources have been released
        //  */
        // template<size_t I>
        // decltype(auto) get() const {
        //     static_assert(I < sizeof...(Resources), "Invalid resource index");
        //     if (m_released) throw std::logic_error("Resource released");
        //     return std::get<I>(m_resources);
        // }

        /**
         * @brief Safely attempts to access the first resource
         * 
         * @return An optional containing the resource if available, nullopt otherwise
         */
        std::optional<std::reference_wrapper<const std::tuple_element_t<0, decltype(m_resources)>>> try_get() const {
            if (m_released) return std::nullopt;
            return std::cref(std::get<0>(m_resources));
        }

        /**
         * @brief Safely attempts to access a specific resource by index
         * 
         * @tparam I The index of the resource to access
         * @return An optional containing the resource if available, nullopt otherwise
         */
        template <size_t I>
        std::optional<std::reference_wrapper<const std::tuple_element_t<I, decltype(m_resources)>>> try_get() const {
            if (m_released) return std::nullopt;
            static_assert(I < sizeof...(Resources), "Invalid resource index");
            return std::cref(std::get<I>(m_resources));
        }

        // /**
        //  * @brief Sets or replaces the first resource
        //  * 
        //  * @param new_resource The new resource to manage
        //  * @throws std::logic_error if resources have been released
        //  * @throws std::invalid_argument if type doesn't match
        //  */
        // void set(const std::tuple_element_t<0, decltype(m_resources)>& new_resource) {
        //     if (m_released) throw std::logic_error("Resource released");
        //     std::get<0>(m_resources) = new_resource;
        // }

        // /**
        //  * @brief Sets or replaces a specific resource by index
        //  * 
        //  * @tparam I The index of the resource to set
        //  * @param new_resource The new resource to manage
        //  * @throws std::logic_error if resources have been released
        //  * @throws std::invalid_argument if type doesn't match
        //  */
        // template <size_t I>
        // void set(const std::tuple_element_t<I, decltype(m_resources)>& new_resource) {
        //     if (m_released) throw std::logic_error("Resource released");
        //     static_assert(I < sizeof...(Resources), "Invalid resource index");
        //     std::get<I>(m_resources) = new_resource;
        // }

        /**
         * @brief Tries to set or replace the first resource
         * 
         * This method attempts to set the first resource to the new resource provided.
         * It returns 0 if the resource was successfully set, and 1 if the resources have been released.
         * 
         * @param new_resource The new resource to manage
         * @return 0 if the resource was set successfully, 1 if resources have been released
         */
        int try_set(const std::tuple_element_t<0, decltype(m_resources)>& new_resource) {
            if (m_released) return 1;
            std::get<0>(m_resources) = new_resource;
            return 0;
        }

        /**
         * @brief Tries to set or replace a specific resource by index
         * 
         * This method attempts to set a specific resource at index `I` to the new resource provided.
         * It returns 0 if the resource was successfully set, and 1 if the resources have been released.
         * 
         * @tparam I The index of the resource to set
         * @param new_resource The new resource to manage
         * @return 0 if the resource was set successfully, 1 if resources have been released
         * @throws std::invalid_argument if index `I` is out of bounds
         */
        template <size_t I>
        int try_set(const std::tuple_element_t<I, decltype(m_resources)>& new_resource) {
            if (m_released) return 1;
            static_assert(I < sizeof...(Resources), "Invalid resource index");
            std::get<I>(m_resources) = new_resource;
            return 0;
        }

        /**
         * @brief Checks if all resources are valid and have not been released
         * 
         * Uses the ValidityCheck trait for each resource type to determine validity
         * 
         * @return true if all resources are valid and not released, false otherwise
         */
        explicit operator bool() const {
            return !m_released && std::apply([](const auto&... args) {
                return (ValidityCheck<decltype(args)>::check(args) && ...);
            }, m_resources);
        }

        /**
         * @brief Explicitly releases resources before destruction
         * 
         * Calls the deleter and marks resources as released
         */
        void release() noexcept { cleanup(); }

        // /**
        //  * @brief Transfers ownership of resources to caller
        //  * 
        //  * After calling steal(), the ResourceGuard no longer manages the resources,
        //  * and the caller is responsible for cleanup
        //  * 
        //  * @return Tuple containing all resources
        //  * @throws std::logic_error if resources have already been released
        //  */
        // std::tuple<Resources...> steal() {
        //     if (m_released) throw std::logic_error("Already released");
        //     m_released = true;
        //     return std::move(m_resources);
        // }

        /**
         * @brief Copy constructor (deleted)
         * 
         * ResourceGuard doesn't support copying to ensure clear ownership semantics
         */
        ResourceGuard(const ResourceGuard&) = delete;
        
        /**
         * @brief Copy assignment operator (deleted)
         * 
         * ResourceGuard doesn't support copying to ensure clear ownership semantics
         */
        ResourceGuard& operator=(const ResourceGuard&) = delete;
    };

    /**
     * @brief Helper function to create ResourceGuard instances with type deduction
     * 
     * This function template automatically deduces types for ResourceGuard creation,
     * simplifying its usage with the correct template argument order (Deleter first, then Resources).
     * 
     * @tparam Deleter The type of deleter function/object
     * @tparam Args The types of resources to manage
     * @param deleter Function object that will be called to clean up resources
     * @param args The resources to manage
     * @return A ResourceGuard instance managing the given resources
     * 
     * @example
     * // Example: Managing a FILE* resource
     * auto file = make_scoped_ref(
     *     [](FILE* f) { if(f) fclose(f); },
     *     fopen("example.txt", "r")
     * );
     * 
     * // Example: Managing multiple resources
     * auto resources = make_scoped_ref(
     *     [](void* p1, int* p2) { 
     *         if (p1) free(p1); 
     *         if (p2) delete p2; 
     *     },
     *     malloc(100),
     *     new int(42)
     * );
     */
    template<typename Deleter, typename... Args>
    auto make_resource_guard(Deleter&& deleter, Args&&... args) {
        return ResourceGuard<
            std::decay_t<Deleter>,      // Deleter type first
            std::decay_t<Args>...       // Resource types after
        >(
            std::forward<Deleter>(deleter),
            std::forward<Args>(args)...
        );
    }

} // namespace ResourceGuard