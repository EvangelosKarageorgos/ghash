/*******************************************************************************
 *  Project: ghash
 *  Purpose: General use C/C++ open addressing hash table structures
 *  Author: Evangelos Karageorgos, karageorgos.evangelos@gmail.com
 *  Languages: C/C++
 *******************************************************************************
 *  MIT License
 *
 *  Copyright (c) 2023 Evangelos Karageorgos
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *******************************************************************************/

/*********************
 *  file: ghash.h    *
 *  version: 0.0.1   *
 *********************/

#pragma once
#ifndef HT_ONCE_GHASH_H
#define HT_ONCE_GHASH_H

/* --------------------------------------------------------------------------------------
                                    C HEADER MACROS
   -------------------------------------------------------------------------------------- */

#define HT_METADATA_TYPE unsigned char
#define HT_HASH_TYPE unsigned long
#define HT_PADDING_SIZE 4
#define HT_INDEX_TYPE long

#define HT_GET_METADATA_TABLE(hash_table) ((HT_METADATA_TYPE*) (hash_table))

#define HT_GET_HASHSES_TABLE(hash_table, table_size) ((HT_HASH_TYPE*) ((char*)(hash_table) + sizeof(HT_METADATA_TYPE) * table_size + HT_PADDING_SIZE))
#define HT_GET_PADDING_TABLE(hash_table, table_size) ((HT_HASH_TYPE*) ((char*)(hash_table) + sizeof(HT_METADATA_TYPE) * table_size))

#define HT_GET_VALUES_TABLE(hash_table, table_size, VALUE_ELEMENT_TYPE) ((VALUE_ELEMENT_TYPE*) (((char*)(HT_GET_HASHSES_TABLE(hash_table, table_size))) + sizeof(HT_HASH_TYPE) * table_size))

#define HT_GET_TABLES(hash_table, table_size, VALUE_ELEMENT_TYPE, VALUE_ELEMENT_SIZE) \
    HT_METADATA_TYPE* ht_metadata_table = HT_GET_METADATA_TABLE(hash_table); \
    HT_HASH_TYPE* ht_hashes_table = HT_GET_HASHSES_TABLE(hash_table, table_size); \
    VALUE_ELEMENT_TYPE* ht_values_table = HT_GET_VALUES_TABLE(hash_table, table_size, VALUE_ELEMENT_TYPE);

#define HT_METADATA_SIZE(table_size) (table_size * sizeof(HT_METADATA_TYPE))

#define HT_VALUES_SIZE(table_size, VALUE_ELEMENT_SIZE) (table_size * VALUE_ELEMENT_SIZE)

#define HT_TABLE_SIZE(table_size, VALUE_ELEMENT_SIZE) (table_size * (sizeof(HT_METADATA_TYPE) + sizeof(HT_HASH_TYPE) + VALUE_ELEMENT_SIZE) + HT_PADDING_SIZE)

#define HT_VALUE_VALID(metadata) ((metadata & 0xC0) == 0x80)

#define HT_FIND_INDEX_BEGIN(hash, modded_hash, hash_table, table_size) \
    HT_METADATA_TYPE* ht_metadata_table = HT_GET_METADATA_TABLE(hash_table); \
    HT_HASH_TYPE* ht_hashes_table = HT_GET_HASHSES_TABLE(hash_table, table_size); \
    HT_METADATA_TYPE truncated_hash = modded_hash & 0x3F; \
    unsigned long index = modded_hash; \
    size_t i; \
    for(i=0; i<table_size; i++){ \
        unsigned char metadata = ht_metadata_table[index]; \
        unsigned char bits = metadata & 0xC0; \
        switch(bits){ \
        case 0x80:{ \
            unsigned char hl1 = metadata & 0x3f; \
            if(hl1 == truncated_hash){ \
                HT_HASH_TYPE hl2 = ht_hashes_table[index]; \
                if(hl2 == hash){

#define HT_FIND_INDEX_END(table_size, not_found_value) \
                } \
            } \
        } break; \
        case 0x00: \
            return not_found_value; \
            break; \
        default: \
            break; \
        } \
        if(index == table_size-1){ \
            index = 0; \
        } else { \
            index++; \
        } \
    } \
    return not_found_value;


#define HT_FIND_FREE_INDEX_BEGIN(hash, modded_hash, hash_table, table_size) \
    HT_METADATA_TYPE* ht_metadata_table = HT_GET_METADATA_TABLE(hash_table); \
    HT_HASH_TYPE* ht_hashes_table = HT_GET_HASHSES_TABLE(hash_table, table_size); \
    HT_METADATA_TYPE truncated_hash = modded_hash & 0x3F; \
    unsigned long index = modded_hash; \
    long free_index = -1; \
    size_t i; \
    for(i=0; i<table_size; i++){ \
        unsigned char metadata = ht_metadata_table[index]; \
        unsigned char bits = metadata & 0xC0; \
        switch(bits){ \
        case 0x80:{ \
            unsigned char hl1 = metadata & 0x3f; \
            if(hl1 == truncated_hash){ \
                HT_HASH_TYPE hl2 = ht_hashes_table[index]; \
                if(hl2 == hash){

#define HT_FIND_FREE_INDEX_END(table_size) \
                } \
            } \
        } break; \
        case 0x00: \
            if(free_index < 0){ \
                return index; \
            } else {\
                return free_index; \
            } \
            break; \
        case 0x40: \
            if(free_index < 0){ \
                free_index = index; \
            } \
            break; \
        default: \
            break; \
        } \
        if(index == table_size-1){ \
            index = 0; \
        } else { \
            index++; \
        } \
    } \
    return free_index;


#define HT_GET_GUARANTEED_FREE_INDEX(modded_hash, hash_table, table_size) \
    HT_METADATA_TYPE* ht_metadata_table = HT_GET_METADATA_TABLE(hash_table); \
    unsigned long index = modded_hash; \
    size_t i; \
    for(i=0; i<table_size; i++){ \
        unsigned char metadata = ht_metadata_table[index]; \
        unsigned char bits = metadata & 0xC0; \
        switch(bits){ \
        case 0x80: \
            break; \
        case 0x00: case 0x40: \
            return index; \
            break; \
        default: \
            break; \
        } \
        if(index == table_size-1){ \
            index = 0; \
        } else { \
            index++; \
        } \
    } \
    return -1;

#define HT_INSERT_ENTRY(hash, modded_hash, index, hash_table, table_size) \
    HT_GET_METADATA_TABLE(hash_table)[index] = 0x80 | (modded_hash & 0x3F); \
    HT_GET_HASHSES_TABLE(hash_table, table_size)[index] = hash; \

#define HT_DELETE_ENTRY(index, hash_table, table_size) \
    HT_GET_METADATA_TABLE(hash_table)[index] = 0x40;





#ifdef __cplusplus

#include "string.h"

namespace ghash{
    using hash_type = HT_HASH_TYPE;
    using index_type = HT_INDEX_TYPE;

    enum class CopyPolicy{
        duplicate_source,
        keep_target_capacity,
        keep_source_capacity,
        minimal_capacity
    };

    enum class OverlappingPolicy{
        ignore_duplicates,
        replace_duplicates
    };

    template<typename V>
    struct no_filter{
        bool operator()(hash_type, const V&) const noexcept{
            return true;
        }
    };

    template<class K, class V>
    struct StdPairKvpAdapter{
        using pair_type = typename std::pair<K, V>;
        using key_type = K;
        using value_type = V;
        key_type& key(pair_type& kvp) const noexcept{
            return kvp.first;
        }
        const key_type& key(const pair_type& kvp) const noexcept{
            return kvp.first;
        }
        key_type&& key(pair_type&& kvp) const noexcept{
            return std::move(kvp.first);
        }
        value_type& value(pair_type& kvp) const noexcept{
            return kvp.second;
        }
        const value_type& value(const pair_type& kvp) const noexcept{
            return kvp.second;
        }
        value_type&& value(pair_type&& kvp) const noexcept{
            return std::move(kvp.second);
        }
    };

    struct insert_result{
        insert_result(index_type index) noexcept : index(index) {}
        insert_result(const insert_result& src) noexcept : index(src.index) {}
        insert_result(index_type index, bool inserted) noexcept {
            this->index = index;
            if(!inserted){
                index = -index - 1;
            }
        }
        index_type get_index() const noexcept{
            if(index>0)
                return index;
            else
                return -(index+1);
        }
        bool is_inserted() const noexcept {
            return index >= 0;
        }
        index_type index;
    };

    /* --------------------------------------------------------------------------------------
                                        DIRECT TABLES
       -------------------------------------------------------------------------------------- */

    template<
        class V,
        class Allocator = std::allocator<char>
    >
    class hash_table_container : public Allocator{
    public:
        using element_type = V;
        using allocator = Allocator;
        const float minimum_table_size = 8;
        const float max_load_factor = 0.8;

        /* ------------------------- constructors ---------------------------- */

        explicit hash_table_container(size_t capacity=0, Allocator&& alloc=Allocator()) : Allocator(std::move(alloc)) {
            if(capacity > 0){
                set_initial_capacity(capacity);
            } else {
                m_hash_table = nullptr;
                m_table_size = 0;
                m_elements = 0;
                m_elements_to_expand = 0;
            }
        }

        explicit hash_table_container(size_t capacity, const Allocator& alloc) : Allocator(alloc) {
            if(capacity > 0){
                set_initial_capacity(capacity);
            } else {
                m_hash_table = nullptr;
                m_table_size = 0;
                m_elements = 0;
                m_elements_to_expand = 0;
            }
        }

        ~hash_table_container(){
            if(m_hash_table != nullptr){
                if(m_elements > 0)
                    delete_elements(m_hash_table, m_table_size);
                mem_free(m_hash_table, m_table_size);
            }
        }

        hash_table_container(const hash_table_container& src){
            if(src.m_elements == 0){
                m_hash_table = nullptr;
                m_table_size = 0;
                m_elements = 0;
                m_elements_to_expand = 0;
            } else {
                set_initial_capacity(src.m_elements);
                copy_elements(src.m_hash_table, src.m_table_size);
            }
        }

        hash_table_container(hash_table_container&& src) noexcept{
            if (std::allocator_traits<Allocator>::propagate_on_container_move_assignment::value){
                static_cast<Allocator&>(*this) = std::move(static_cast<Allocator&>(src));
            }
            m_hash_table = src.m_hash_table;
            m_table_size = src.m_table_size;
            m_elements = src.m_elements;
            m_elements_to_expand = src.m_elements_to_expand;
            src.m_hash_table = nullptr;
            src.m_table_size = 0;
            src.m_elements = 0;
            src.m_elements_to_expand = 0;
        }

        hash_table_container& operator=(const hash_table_container& src){
            if(&src != this){
                if(m_hash_table != nullptr){
                    clear();
                    expand_capacity(src.m_elements);
                } else {
                    if(src.m_elements > 0)
                        set_initial_capacity(src.m_elements);
                }
                if(src.m_elements > 0)
                    copy_elements(src.m_hash_table, src.m_table_size);
            }
            return *this;
        }

        hash_table_container& operator=(hash_table_container&& src){
            if(&src != this){
                if(m_hash_table != nullptr){
                    if(m_elements > 0)
                        delete_elements(m_hash_table, m_table_size);
                    mem_free(m_hash_table, m_table_size);
                }
                if (std::allocator_traits<Allocator>::propagate_on_container_move_assignment::value){
                    static_cast<Allocator&>(*this) = std::move(static_cast<Allocator&>(src));
                }
                m_hash_table = src.m_hash_table;
                m_table_size = src.m_table_size;
                m_elements = src.m_elements;
                m_elements_to_expand = src.m_elements_to_expand;
                src.m_hash_table = nullptr;
                src.m_table_size = 0;
                src.m_elements = 0;
                src.m_elements_to_expand = 0;
            }
            return *this;
        }

        /* ------------------------ common methods ------------------------- */

        void clear(){
            if(m_elements > 0)
                delete_elements(m_hash_table, m_table_size);
            invalidate_elements(m_hash_table, m_table_size);
            m_elements_to_expand += m_elements;
            m_elements = 0;
        }

        void swap(hash_table_container& other) noexcept{
            if (std::allocator_traits<Allocator>::propagate_on_container_swap::value){
                std::swap(static_cast<Allocator&>(*this), static_cast<Allocator&>(other));
            }
            std::swap(m_hash_table, other.m_hash_table);
            std::swap(m_table_size, other.m_table_size);
            std::swap(m_elements, other.m_elements);
            std::swap(m_elements_to_expand, other.m_elements_to_expand);
        }

        size_t size() const noexcept {return m_elements;}

        hash_type get_hash_of(index_type index) const noexcept{
            return HT_GET_HASHSES_TABLE(m_hash_table, m_table_size)[index];
        }

        template<typename F>
        void iterate(F func) const{
            HT_GET_TABLES(m_hash_table, m_table_size, V, sizeof(V))
            for(size_t index=0; index < m_table_size; index++){
                if(HT_VALUE_VALID(ht_metadata_table[index])){
                    func(ht_hashes_table[index], ht_values_table[index]);
                }
            }
        }

        template<typename F>
        void self_filter(F filter){
            if(this->m_elements > 0){
                HT_GET_TABLES(this->m_hash_table, this->m_table_size, V, sizeof(V))
                for(size_t index=0; index < this->m_table_size; index++){
                    if(HT_VALUE_VALID(ht_metadata_table[index])){
                        if(!filter(ht_hashes_table[index], ht_values_table[index])){
                            ht_values_table[index].~V();
                            m_elements--;
                            m_elements_to_expand++;
                            HT_DELETE_ENTRY(index, m_hash_table, m_table_size)
                        }
                    }
                }
            }
        }

        template<typename F=no_filter<V>>
        void copy_into_and_replace(hash_table_container& target, F filter=F(), CopyPolicy copy_policy = CopyPolicy::keep_target_capacity) const{
            target.clear();
            if(copy_policy == CopyPolicy::duplicate_source){
                target.change_table_size(this->m_table_size);
                if(this->m_elements > 0){
                    HT_METADATA_TYPE* dst_metadata_table = HT_GET_METADATA_TABLE(target.m_hash_table);
                    hash_type* dst_hashes_table = HT_GET_HASHSES_TABLE(target.m_hash_table, target.m_table_size);
                    V* dst_values_table = HT_GET_VALUES_TABLE(target.m_hash_table, target.m_table_size, V);
                    HT_GET_TABLES(this->m_hash_table, this->m_table_size, V, sizeof(V))
                    memcpy(dst_metadata_table, ht_metadata_table, HT_METADATA_SIZE(target.m_table_size));
                    for(size_t index=0; index < this->m_table_size; index++){
                        if(HT_VALUE_VALID(ht_metadata_table[index])){
                            if(filter(ht_hashes_table[index], ht_values_table[index])){
                                dst_metadata_table[index] = ht_metadata_table[index];
                                dst_hashes_table[index] = ht_hashes_table[index];
                                ::new (static_cast<void*>(&(dst_values_table[index]))) V(ht_values_table[index]);
                                target.m_elements++;
                                target.m_elements_to_expand--;
                            } else {
                                HT_DELETE_ENTRY(index, target.m_hash_table, target.m_table_size)
                            }
                        } else {
                            dst_metadata_table[index] = ht_metadata_table[index];
                        }
                    }
                }
            } else {
                switch(copy_policy){
                case CopyPolicy::minimal_capacity:
                    target.set_capacity(0);
                    break;
                case CopyPolicy::keep_source_capacity:
                    target.set_capacity(this->m_elements);
                    break;
                case CopyPolicy::keep_target_capacity:
                    break;
                default:
                    break;
                }
                if(this->m_elements > 0){
                    HT_GET_TABLES(this->m_hash_table, this->m_table_size, V, sizeof(V))
                    for(size_t index=0; index < this->m_table_size; index++){
                        if(HT_VALUE_VALID(ht_metadata_table[index])){
                            if(filter(ht_hashes_table[index], ht_values_table[index])){
                                target.check_and_expand_full_capacity();
                                hash_type hash = ht_hashes_table[index];
                                hash_type modded_hash = target.calculate_modded_hash(hash);
                                index_type new_index = target.find_guaranteed_free_index(modded_hash);
                                HT_INSERT_ENTRY(hash, modded_hash, new_index, target.m_hash_table, target.m_table_size)
                                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(target.m_hash_table, target.m_table_size, V)[new_index]))) V(ht_values_table[index]);
                                target.m_elements++;
                                target.m_elements_to_expand--;
                            }
                        }
                    }
                }
            }
        }

        /* ------------------------ capacity and rehashing management interface ------------------------- */

        /* get the total available capacity */
        size_t get_capacity(){
            return m_elements + m_elements_to_expand;
        }

        /* Forces rehashing, and optionally shrinking, the table. */
        void rehash_table(bool shrink_capacity=true){
            if(shrink_capacity){
                set_capacity(0, true);
            } else {
                if(m_hash_table != nullptr){
                    recalculate_table(m_table_size);
                }
            }
        }

        /* Try to set the specified capacity, and optionally, force rehashing the table. */
        /* Returns true if a rehashing took place. */
        bool set_capacity(size_t capacity, bool force_rehash=false){
            size_t new_table_size = calculate_minimum_table_size(capacity);
            if(m_table_size != new_table_size){
                bool recalculated_table = change_table_size(new_table_size);
                if(!recalculated_table && force_rehash){
                    if(m_hash_table != nullptr){
                        recalculate_table(m_table_size);
                    }
                    recalculated_table = true;
                }
                return recalculated_table;
            } else {
                if(force_rehash){
                    if(m_hash_table != nullptr){
                        recalculate_table(m_table_size);
                    }
                    return true;
                }
                return false;
            }
        }

        /* If the current capacity is sufficient to insert an element, return false. */
        /* Otherwise, expand the capacity and return true */
        bool check_and_expand_full_capacity(){
            if(m_elements_to_expand == 0){
                expand_capacity(m_elements + 1);
                return true;
            } else {
                return false;
            }
        }

        /* Try to set the specified capacity, but the current capacity may only expand. */
        bool expand_capacity(size_t capacity){
            size_t new_table_size = calculate_minimum_table_size(capacity);
            if(m_table_size < new_table_size){
                return change_table_size(new_table_size);
            } else {
                return false;
            }
        }

        /* ---------------------------- iterator interface ------------------------------ */

        struct iterator;
        struct const_iterator;

        struct reverse_iterator;
        struct const_reverse_iterator;

        iterator begin() noexcept{ if(m_hash_table == nullptr) return at_index(0); else return iterator(HT_GET_METADATA_TABLE(m_hash_table), HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V), nullptr);}
        const_iterator begin()const noexcept{ if(m_hash_table == nullptr) return at_index(0); else return const_iterator(HT_GET_METADATA_TABLE(m_hash_table), HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V), nullptr);}
        const_iterator cbegin()const noexcept{ if(m_hash_table == nullptr) return at_index(0); else return const_iterator(HT_GET_METADATA_TABLE(m_hash_table), HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V), nullptr);}

        reverse_iterator rbegin() noexcept{ if(m_hash_table == nullptr) return at_index_r(-1); else return reverse_iterator(&(HT_GET_METADATA_TABLE(m_hash_table)[m_table_size-1]), &(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[m_table_size-1]), &(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[-1]), nullptr);}
        const_reverse_iterator rbegin()const noexcept{ if(m_hash_table == nullptr) return at_index_r(-1); else return const_reverse_iterator(&(HT_GET_METADATA_TABLE(m_hash_table)[m_table_size-1]), &(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[m_table_size-1]), &(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[-1]), nullptr);}
        const_reverse_iterator crbegin()const noexcept{ if(m_hash_table == nullptr) return at_index_r(-1); else return const_reverse_iterator(&(HT_GET_METADATA_TABLE(m_hash_table)[m_table_size-1]), &(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[m_table_size-1]), &(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[-1]), nullptr);}

        iterator end() noexcept{ return at_index(m_table_size);}
        const_iterator end() const noexcept{ return at_index(m_table_size);}
        const_iterator cend() const noexcept{ return at_index(m_table_size);}

        reverse_iterator rend() noexcept{ return at_index_r(-1);}
        const_reverse_iterator rend() const noexcept{ return at_index_r(-1);}
        const_reverse_iterator crend() const noexcept{ return at_index_r(-1);}

        iterator at_index(index_type index) noexcept{ return iterator(&(HT_GET_METADATA_TABLE(m_hash_table)[index]), &(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[index]));}
        const_iterator at_index(index_type index) const noexcept{ return const_iterator(&(HT_GET_METADATA_TABLE(m_hash_table)[index]), &(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[index]));}

        reverse_iterator at_index_r(index_type index) noexcept{ return reverse_iterator(&(HT_GET_METADATA_TABLE(m_hash_table)[index]), &(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[index]), &(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[-1]));}
        const_reverse_iterator at_index_r(index_type index) const noexcept{ return const_reverse_iterator(&(HT_GET_METADATA_TABLE(m_hash_table)[index]), &(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[index]), &(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[-1]));}
    protected:

        hash_type calculate_modded_hash (hash_type hash) const noexcept{
            return (hash_type)(hash % m_table_size);
        }

        index_type find_guaranteed_free_index(hash_type modded_hash) const noexcept{
            HT_GET_GUARANTEED_FREE_INDEX(modded_hash, m_hash_table, m_table_size)
        }

        /* ----------------------------- memory allocation --------------------------- */

        void* mem_alloc(size_t size){
            return Allocator::allocate(size);
        }

        void mem_free(void* table, size_t size) noexcept{
            Allocator::deallocate(static_cast<char*>(table), size);
        }

        /* ----------------------------- table operations helpers --------------------------- */

        size_t calculate_table_size(size_t capacity) const noexcept{
            if(capacity < minimum_table_size){
                return minimum_table_size;
            } else {
                size_t result = 0;
                capacity = capacity - 1;
                while(capacity > 0){
                    capacity = capacity >> 1;
                    result++;
                }
                return 1 << result;
            }
        }

        size_t calculate_minimum_table_size(size_t capacity) const noexcept{
            if(capacity < m_elements)
                capacity = m_elements;
            size_t table_size = calculate_table_size(capacity);
            while(capacity > (table_size * max_load_factor))
                table_size = table_size << 1;
            return table_size;
        }

        void set_initial_capacity(size_t capacity){
            size_t table_size = calculate_table_size(capacity);
            while(capacity > (table_size * max_load_factor))
                table_size = table_size << 1;
            m_hash_table = allocate_table(table_size);
            m_table_size = table_size;
            m_elements = 0;
            m_elements_to_expand = table_size * max_load_factor;
        }

        void set_initial_table_size(size_t table_size){
            m_hash_table = allocate_table(table_size);
            m_table_size = table_size;
            m_elements = 0;
            m_elements_to_expand = table_size * max_load_factor;
        }

        void* allocate_table(size_t table_size){
            if(table_size == 0){
                return nullptr;
            } else {
                size_t total_table_size = HT_TABLE_SIZE(table_size, sizeof(V));
                void* hash_table = mem_alloc(total_table_size);
                memset(hash_table, 0, total_table_size); // for debugging purposes
                memset(hash_table, 0, HT_METADATA_SIZE(table_size));
                memset(HT_GET_PADDING_TABLE(hash_table, table_size), 0xff, HT_PADDING_SIZE);
                return hash_table;
            }
        }

        bool change_table_size(size_t new_table_size){
            if(m_table_size != new_table_size){
                recalculate_table(new_table_size);
                return true;
            } else {
                return false;
            }
        }

        void recalculate_table(size_t new_table_size){
            size_t prev_table_size = m_table_size;
            void* prev_hash_table = m_hash_table;
            size_t prev_elements = m_elements;
            void* new_table = allocate_table(new_table_size);
            m_hash_table = new_table;
            m_table_size = new_table_size;
            m_elements = 0;
            m_elements_to_expand = new_table_size * max_load_factor;
            if(prev_hash_table != nullptr){
                if(prev_elements > 0){
                    move_elements(prev_hash_table, prev_table_size);
                    delete_elements(prev_hash_table, prev_table_size);
                }
                mem_free(prev_hash_table, prev_table_size);
            }
        }

        /* --------------------------- bulk element operations ----------------------------- */

        void copy_elements(void* source_hash_table, size_t source_table_size){
            HT_GET_TABLES(source_hash_table, source_table_size, V, sizeof(V))
            for(size_t index=0; index < source_table_size; index++){
                if(HT_VALUE_VALID(ht_metadata_table[index])){
                    hash_type hash = ht_hashes_table[index];
                    hash_type modded_hash = calculate_modded_hash(hash);
                    index_type new_index = find_guaranteed_free_index(modded_hash);
                    HT_INSERT_ENTRY(hash, modded_hash, new_index, m_hash_table, m_table_size)
                    ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[new_index]))) V(ht_values_table[index]);
                    m_elements++;
                    m_elements_to_expand--;
                }
            }
        }

        template<typename F>
        void copy_elements(void* source_hash_table, size_t source_table_size, F filter){
            HT_GET_TABLES(source_hash_table, source_table_size, V, sizeof(V))
            for(size_t index=0; index < source_table_size; index++){
                if(HT_VALUE_VALID(ht_metadata_table[index])){
                    hash_type hash = ht_hashes_table[index];
                    hash_type modded_hash = calculate_modded_hash(hash);
                    if(filter(hash, ht_values_table[index])){
                        index_type new_index = find_guaranteed_free_index(modded_hash);
                        HT_INSERT_ENTRY(hash, modded_hash, new_index, m_hash_table, m_table_size)
                        ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[new_index]))) V(ht_values_table[index]);
                        m_elements++;
                        m_elements_to_expand--;
                    }
                }
            }
        }

        void move_elements(void* source_hash_table, size_t source_table_size){
            HT_GET_TABLES(source_hash_table, source_table_size, V, sizeof(V))
            for(size_t index=0; index < source_table_size; index++){
                if(HT_VALUE_VALID(ht_metadata_table[index])){
                    hash_type hash = ht_hashes_table[index];
                    hash_type modded_hash = calculate_modded_hash(hash);
                    index_type new_index = find_guaranteed_free_index(modded_hash);
                    HT_INSERT_ENTRY(hash, modded_hash, new_index, m_hash_table, m_table_size)
                    ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[new_index]))) V(std::move(ht_values_table[index]));
                    m_elements++;
                    m_elements_to_expand--;
                }
            }
        }

        template<typename F>
        void move_elements(void* source_hash_table, size_t source_table_size, F filter){
            HT_GET_TABLES(source_hash_table, source_table_size, V, sizeof(V))
            for(size_t index=0; index < source_table_size; index++){
                if(HT_VALUE_VALID(ht_metadata_table[index])){
                    hash_type hash = ht_hashes_table[index];
                    hash_type modded_hash = calculate_modded_hash(hash);
                    if(filter(hash, ht_values_table[index])){
                        index_type new_index = find_guaranteed_free_index(modded_hash);
                        HT_INSERT_ENTRY(hash, modded_hash, new_index, m_hash_table, m_table_size)
                        ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, V)[new_index]))) V(std::move(ht_values_table[index]));
                        m_elements++;
                        m_elements_to_expand--;
                    }
                }
            }
        }

        void delete_elements(void* source_hash_table, size_t source_table_size){
            HT_METADATA_TYPE* ht_metadata_table = HT_GET_METADATA_TABLE(source_hash_table);
            V* ht_values_table = HT_GET_VALUES_TABLE(source_hash_table, source_table_size, V);
            for(size_t index=0; index < source_table_size; index++){
                if(HT_VALUE_VALID(ht_metadata_table[index])){
                    ht_values_table[index].~V();
                }
            }
        }

        void invalidate_elements(void* hash_table, size_t table_size) noexcept{
            memset(hash_table, 0, HT_METADATA_SIZE(table_size));
        }

        void* m_hash_table;
        size_t m_table_size;
        size_t m_elements;
        size_t m_elements_to_expand;
    };

    /* ---------------------------- Iterators ------------------------------- */

    template<class V, class Allocator>
    struct hash_table_container<V, Allocator>::iterator{
        typedef std::forward_iterator_tag iterator_category;
        typedef V value_type;
        typedef V* pointer;
        typedef V& reference;
        iterator(HT_METADATA_TYPE *metadata_ptr, V* value_ptr) noexcept : metadata_ptr(metadata_ptr), value_ptr(value_ptr){}
        iterator(HT_METADATA_TYPE *metadata_ptr, V* value_ptr, void*) noexcept : metadata_ptr(metadata_ptr), value_ptr(value_ptr){if((*metadata_ptr & 0xC0) != 0x80)next_valid();}
        HT_METADATA_TYPE *metadata_ptr;
        V* value_ptr;
        V* value_end_ptr;
        bool operator==(const iterator& it) const noexcept {return value_ptr == it.value_ptr;}
        bool operator!=(const iterator& it) const noexcept {return value_ptr != it.value_ptr;}
        V& operator*() const noexcept {return *value_ptr;}
        V* operator->() const noexcept {return value_ptr;}
        operator bool() const noexcept {return value_ptr != nullptr && ((*metadata_ptr & 0xC0) == 0x80);}
        void next_valid() noexcept{
            HT_METADATA_TYPE flags;
            do{
                metadata_ptr++;
                value_ptr++;
                flags = (*metadata_ptr & 0xC0);
            } while((flags != 0xC0) && (flags != 0x80));
        }
        iterator& operator++() noexcept {next_valid(); return *this;}
        iterator& operator++(int) noexcept {next_valid(); return *this;}
    };

    template<class V, class Allocator>
    struct hash_table_container<V, Allocator>::const_iterator{
        typedef std::forward_iterator_tag iterator_category;
        typedef V value_type;
        typedef const V* pointer;
        typedef const V& reference;
        const_iterator(HT_METADATA_TYPE *metadata_ptr, V* value_ptr) noexcept : metadata_ptr(metadata_ptr), value_ptr(value_ptr){}
        const_iterator(HT_METADATA_TYPE *metadata_ptr, V* value_ptr, void*) noexcept : metadata_ptr(metadata_ptr), value_ptr(value_ptr){if((*metadata_ptr & 0xC0) != 0x80)next_valid();}
        HT_METADATA_TYPE *metadata_ptr;
        V* value_ptr;
        V* value_end_ptr;
        bool operator==(const const_iterator& it) const noexcept {return value_ptr == it.value_ptr;}
        bool operator!=(const const_iterator& it) const noexcept {return value_ptr != it.value_ptr;}
        const V& operator*() const noexcept {return *value_ptr;}
        const V* operator->() const noexcept {return value_ptr;}
        operator bool() const noexcept {return value_ptr != nullptr && ((*metadata_ptr & 0xC0) == 0x80);}
        void next_valid() noexcept{
            HT_METADATA_TYPE flags;
            do{
                metadata_ptr++;
                value_ptr++;
                flags = (*metadata_ptr & 0xC0);
            } while((flags != 0xC0) && (flags != 0x80));
        }
        const_iterator& operator++() noexcept {next_valid(); return *this;}
        const_iterator& operator++(int) noexcept {next_valid();return *this;}
    };

    template<class V, class Allocator>
    struct hash_table_container<V, Allocator>::reverse_iterator{
        typedef std::forward_iterator_tag iterator_category;
        typedef V value_type;
        typedef V* pointer;
        typedef V& reference;
        reverse_iterator(HT_METADATA_TYPE *metadata_ptr, V* value_ptr, V* value_end_ptr) noexcept : metadata_ptr(metadata_ptr), value_ptr(value_ptr), value_end_ptr(value_end_ptr){}
        reverse_iterator(HT_METADATA_TYPE *metadata_ptr, V* value_ptr, V* value_end_ptr, void*) noexcept : metadata_ptr(metadata_ptr), value_ptr(value_ptr), value_end_ptr(value_end_ptr){if((*metadata_ptr & 0xC0) != 0x80)next_valid();}
        HT_METADATA_TYPE *metadata_ptr;
        V* value_ptr;
        V* value_end_ptr;
        bool operator==(const reverse_iterator& it) const noexcept {return value_ptr == it.value_ptr;}
        bool operator!=(const reverse_iterator& it) const noexcept {return value_ptr != it.value_ptr;}
        V& operator*() const noexcept {return *value_ptr;}
        V* operator->() const noexcept {return value_ptr;}
        operator bool() const noexcept {return (value_ptr != value_end_ptr) && ((*metadata_ptr & 0xC0) == 0x80);}
        void next_valid() noexcept{
            do{
                metadata_ptr--;
                value_ptr--;
            } while((value_ptr != value_end_ptr) && ((*metadata_ptr & 0xC0) != 0x80));
        }
        reverse_iterator& operator++() noexcept {next_valid(); return *this;}
        reverse_iterator& operator++(int) noexcept {next_valid(); return *this;}
    };

    template<class V, class Allocator>
    struct hash_table_container<V, Allocator>::const_reverse_iterator{
        typedef std::forward_iterator_tag iterator_category;
        typedef V value_type;
        typedef const V* pointer;
        typedef const V& reference;
        const_reverse_iterator(HT_METADATA_TYPE *metadata_ptr, V* value_ptr, V* value_end_ptr) noexcept : metadata_ptr(metadata_ptr), value_ptr(value_ptr), value_end_ptr(value_end_ptr){}
        const_reverse_iterator(HT_METADATA_TYPE *metadata_ptr, V* value_ptr, V* value_end_ptr, void*) noexcept : metadata_ptr(metadata_ptr), value_ptr(value_ptr), value_end_ptr(value_end_ptr){if((*metadata_ptr & 0xC0) != 0x80)next_valid();}
        HT_METADATA_TYPE *metadata_ptr;
        V* value_ptr;
        V* value_end_ptr;
        bool operator==(const const_reverse_iterator& it) const noexcept {return value_ptr == it.value_ptr;}
        bool operator!=(const const_reverse_iterator& it) const noexcept {return value_ptr != it.value_ptr;}
        const V& operator*() const noexcept {return *value_ptr;}
        const V* operator->() const noexcept {return value_ptr;}
        operator bool() const noexcept {return (value_ptr != value_end_ptr) && ((*metadata_ptr & 0xC0) == 0x80);}
        void next_valid() noexcept{
            do{
                metadata_ptr--;
                value_ptr--;
            } while((value_ptr != value_end_ptr) && ((*metadata_ptr & 0xC0) != 0x80));
        }
        const_reverse_iterator& operator++() noexcept {next_valid(); return *this;}
        const_reverse_iterator& operator++(int) noexcept {next_valid();return *this;}
    };


    /* --------------------------------------------------------------------------------------
                                        SET - DIRECT TABLE
       -------------------------------------------------------------------------------------- */

    template<
        class V,
        class Hash = std::hash<V>,
        class Equal = std::equal_to<V>,
        class Allocator = std::allocator<char>
    >
    class hash_table_set : public hash_table_container<V, Allocator>{
        using BaseClass = hash_table_container<V, Allocator>;
    public:
        using element_type = typename BaseClass::element_type;
        using value_type = V;
        using allocator = Allocator;
        using hash_function = Hash;
        using equality_function = Equal;
        using iterator = typename BaseClass::iterator;
        using const_iterator = typename BaseClass::const_iterator;
        using reverse_iterator = typename BaseClass::reverse_iterator;
        using const_reverse_iterator = typename BaseClass::const_reverse_iterator;
        /* ------------------------- boilerplate ---------------------------- */
        explicit hash_table_set(size_t capacity=0, Allocator&& alloc=Allocator()) : BaseClass(capacity, std::move(alloc)) {}
        explicit hash_table_set(size_t capacity, const Allocator& alloc) : BaseClass(capacity, alloc) {}
        hash_table_set(const hash_table_set& src) : BaseClass(src) {}
        hash_table_set(hash_table_set&& src) noexcept : BaseClass(std::move(src)) {}
        hash_table_set& operator=(const hash_table_set& src) { return static_cast<hash_table_set&>(BaseClass::operator=(src)); }
        hash_table_set& operator=(hash_table_set&& src) { return static_cast<hash_table_set&>(BaseClass::operator=(std::move(src))); }

        /* -------------------------- container operations interface ------------------------------- */

        V& get_value(index_type index)const noexcept{
            return HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index];
        }

        index_type find_index(const V& value) const noexcept{
            hash_type hash = calculate_hash(value);
            return find_index_h(hash, value);
        }

        V* find_ptr(const V& value) const noexcept{
            hash_type hash = calculate_hash(value);
            return find_ptr_h(hash, value);
        }

        // if using normal constructors for elements
        template<typename ...Elms> size_t insert_many(Elms&&... elms){
            this->expand_capacity(this->m_elements+sizeof...(Elms));
            return insert_many_impl(std::forward<Elms>(elms)...);
        };

        // if using normal constructors for elements
        template<typename ...Elms> size_t emplace_many(Elms&&... elms){
            this->expand_capacity(this->m_elements+sizeof...(Elms));
            return emplace_many_impl(std::forward<Elms>(elms)...);
        };

        // if using brace-initialization for elements
        size_t insert_many_il(std::initializer_list<V> elms){
            this->expand_capacity(this->m_elements+elms.size());
            size_t inserted = 0;
            for(auto& v : elms){
                if(insert_value(v) >= 0)
                    inserted++;
            }
            return inserted;
        };

        // if using iterators for elements
        template<class InputIterator> size_t insert_many_it(InputIterator it_start, InputIterator it_end){
            size_t n_inserts = 0;
            for (; it_start != it_end; ++it_start){
                n_inserts += (insert_value(*it_start) >= 0 ? 1 : 0);
            }
            return n_inserts;
        }


        index_type insert_value(const V& value){
            hash_type hash = calculate_hash(value);
            return insert_value_h(hash, value);
        }

        index_type insert_value(V&& value){
            hash_type hash = calculate_hash(value);
            return insert_value_h(hash, std::move(value));
        }

        template<typename... ARGS> index_type emplace_value(ARGS&&... args){
            return insert_value(V(std::forward<ARGS>(args)...));
        }

        insert_result insert_or_find_value(const V& value){
            hash_type hash = calculate_hash(value);
            return insert_or_find_value_h(hash, value);
        }

        insert_result insert_or_find_value(V&& value){
            hash_type hash = calculate_hash(value);
            return insert_or_find_value_h(hash, std::move(value));
        }

        insert_result insert_or_replace_value(const V& value){
            hash_type hash = calculate_hash(value);
            return insert_or_replace_value_h(hash, value);
        }

        insert_result insert_or_replace_value(V&& value){
            hash_type hash = calculate_hash(value);
            return insert_or_replace_value_h(hash, std::move(value));
        }

        template<typename... ARGS> insert_result emplace_or_find_value(ARGS&&... args){
            return insert_or_find_value(V(std::forward<ARGS>(args)...));
        }

        template<typename... ARGS> insert_result emplace_or_replace_value(ARGS&&... args){
            return insert_or_replace_value(V(std::forward<ARGS>(args)...));
        }

        index_type erase_value(const V& value){
            hash_type hash = calculate_hash(value);
            return erase_value_h(hash, value);
        }

        iterator erase_value_and_get_next(const V& value){
            hash_type hash = calculate_hash(value);
            return erase_value_and_get_next_h(hash, value);
        }

        index_type find_index_h(hash_type hash, const V& value) const noexcept{
            hash_type modded_hash = this->calculate_modded_hash(hash);
            return find_existing_index(value, hash, modded_hash);
        }

        V* find_ptr_h(hash_type hash, const V& value) const noexcept{
            hash_type modded_hash = this->calculate_modded_hash(hash);
            return find_existing_ptr(value, hash, modded_hash);
        }

        index_type insert_value_h(hash_type hash, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(value, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index]))) V(value);
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        index_type insert_value_h(hash_type hash, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(value, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index]))) V(std::move(value));
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        insert_result insert_or_find_value_h(hash_type hash, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(value, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index]))) V(value);
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_find_value_h(hash_type hash, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(value, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index]))) V(std::move(value));
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(value, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index] = value;
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index]))) V(value);
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(value, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index] = std::move(value);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index]))) V(std::move(value));
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        template<typename... ARGS> insert_result emplace_or_replace_value_h(hash_type hash, ARGS&&... args){
            V value(std::forward<ARGS>(args)...);
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(value, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index] = std::move(value);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index]))) V(std::move(value));
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        index_type erase_value_h(hash_type hash, const V& value){
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_index(value, hash, modded_hash);
            if(index >= 0){
                HT_DELETE_ENTRY(index, this->m_hash_table, this->m_table_size)
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index].~V();
                this->m_elements--;
                this->m_elements_to_expand++;
            }
            return index;
        }

        iterator erase_value_and_get_next_h(hash_type hash, const V& value){
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_index(value, hash, modded_hash);
            if(index >= 0){
                HT_DELETE_ENTRY(index, this->m_hash_table, this->m_table_size)
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index].~V();
                this->m_elements--;
                this->m_elements_to_expand++;
                return iterator(&(HT_GET_METADATA_TABLE(this->m_hash_table)[index]), &(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[index]), nullptr);
            } else {
                return this->end();
            }
        }

        size_t merge_from(const hash_table_set& source, OverlappingPolicy merge_policy=OverlappingPolicy::ignore_duplicates){
            this->expand_capacity(this->m_elements + source.m_elements);
            size_t result = 0;
            switch(merge_policy){
                case OverlappingPolicy::ignore_duplicates:{
                    HT_GET_TABLES(source.m_hash_table, source.m_table_size, V, sizeof(V))
                    for(size_t index=0; index < source.m_table_size; index++){
                        if(HT_VALUE_VALID(ht_metadata_table[index])){
                            hash_type hash = ht_hashes_table[index];
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type new_index = find_free_index(ht_values_table[index], hash, modded_hash);
                            if(new_index >= 0){
                                HT_INSERT_ENTRY(hash, modded_hash, new_index, this->m_hash_table, this->m_table_size)
                                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[new_index]))) V(ht_values_table[index]);
                                this->m_elements++;
                                this->m_elements_to_expand--;
                                result++;
                            }
                        }
                    }
                } break;
                case OverlappingPolicy::replace_duplicates:{
                    HT_GET_TABLES(source.m_hash_table, source.m_table_size, V, sizeof(V))
                    for(size_t index=0; index < source.m_table_size; index++){
                        if(HT_VALUE_VALID(ht_metadata_table[index])){
                            hash_type hash = ht_hashes_table[index];
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type new_index = find_existing_or_free_index(ht_values_table[index], hash, modded_hash);
                            if(new_index >= 0){
                                if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[new_index])){
                                    HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[new_index] = ht_values_table[index];
                                } else {
                                    HT_INSERT_ENTRY(hash, modded_hash, new_index, this->m_hash_table, this->m_table_size)
                                    ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[new_index]))) V(ht_values_table[index]);
                                    this->m_elements++;
                                    this->m_elements_to_expand--;
                                }
                                result++;
                            }
                        }
                    }
                } break;
                default:
                    break;
            }
            return result;
        }

        size_t merge_from(hash_table_set&& source, OverlappingPolicy merge_policy=OverlappingPolicy::ignore_duplicates){
            this->expand_capacity(this->m_elements + source.m_elements);
            size_t result = 0;
            switch(merge_policy){
                case OverlappingPolicy::ignore_duplicates:{
                    HT_GET_TABLES(source.m_hash_table, source.m_table_size, V, sizeof(V))
                    for(size_t index=0; index < source.m_table_size; index++){
                        if(HT_VALUE_VALID(ht_metadata_table[index])){
                            hash_type hash = ht_hashes_table[index];
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type new_index = find_free_index(ht_values_table[index], hash, modded_hash);
                            if(new_index >= 0){
                                HT_INSERT_ENTRY(hash, modded_hash, new_index, this->m_hash_table, this->m_table_size)
                                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[new_index]))) V(std::move(ht_values_table[index]));
                                this->m_elements++;
                                this->m_elements_to_expand--;
                                result++;
                            }
                        }
                    }
                } break;
                case OverlappingPolicy::replace_duplicates:{
                    HT_GET_TABLES(source.m_hash_table, source.m_table_size, V, sizeof(V))
                    for(size_t index=0; index < source.m_table_size; index++){
                        if(HT_VALUE_VALID(ht_metadata_table[index])){
                            hash_type hash = ht_hashes_table[index];
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type new_index = find_existing_or_free_index(ht_values_table[index], hash, modded_hash);
                            if(new_index >= 0){
                                if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[new_index])){
                                    HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[new_index] = std::move(ht_values_table[index]);
                                } else {
                                    HT_INSERT_ENTRY(hash, modded_hash, new_index, this->m_hash_table, this->m_table_size)
                                    ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V)[new_index]))) V(std::move(ht_values_table[index]));
                                    this->m_elements++;
                                    this->m_elements_to_expand--;
                                }
                                result++;
                            }
                        }
                    }
                } break;
                default:
                    break;
            }
            source.clear();
            return result;
        }

        bool equals(const hash_table_set& other) const noexcept{
            if(this->m_elements != other.m_elements)
                return false;
            if(this->m_table_size < other.m_table_size){
                HT_GET_TABLES(this->m_hash_table, this->m_table_size, V, sizeof(V))
                for(size_t index=0; index < this->m_table_size; index++){
                    if(HT_VALUE_VALID(ht_metadata_table[index])){
                        V* value_ptr = other.find_ptr_h(ht_hashes_table[index], ht_values_table[index]);
                        if(value_ptr == nullptr){
                            return false;
                        }
                    }
                }
                return true;
            } else {
                HT_GET_TABLES(other.m_hash_table, other.m_table_size, V, sizeof(V))
                for(size_t index=0; index < other.m_table_size; index++){
                    if(HT_VALUE_VALID(ht_metadata_table[index])){
                        V* value_ptr = this->find_ptr_h(ht_hashes_table[index], ht_values_table[index]);
                        if(value_ptr == nullptr){
                            return false;
                        }
                    }
                }
                return true;
            }
        }

        template<typename V2, typename Hash2, typename Equal2, typename Alloc2>
        friend bool operator==(const hash_table_set<V2, Hash2, Equal2, Alloc2>& lhs, const hash_table_set<V2, Hash2, Equal2, Alloc2>& rhs);

        template<typename V2, typename Hash2, typename Equal2, typename Alloc2>
        friend bool operator!=(const hash_table_set<V2, Hash2, Equal2, Alloc2>& lhs, const hash_table_set<V2, Hash2, Equal2, Alloc2>& rhs);

        template<typename F=no_filter<V>>
        hash_table_set copy(F filter=F(), CopyPolicy copy_policy = CopyPolicy::keep_source_capacity) const{
            hash_table_set result(0, static_cast<const Allocator&>(*this));
            this->copy_into_and_replace(result, std::forward<F>(filter), copy_policy);
            return result;
        }
    protected:

        size_t insert_many_impl(){return 0;};
        template<typename H, typename ...Elms> size_t insert_many_impl(H &&h, Elms&&... elms){
            return (insert_value(std::forward<H>(h)) >= 0) + insert_many_impl(std::forward<Elms>(elms)...);
        };

        size_t emplace_many_impl(){return 0;};
        template<typename H, typename ...Elms> size_t emplace_many_impl(H &&h, Elms&&... elms){
            return (emplace_value(std::forward<H>(h)) >= 0) + emplace_many_impl(std::forward<Elms>(elms)...);
        };

        hash_type calculate_hash (const V& value) const noexcept{
            return (hash_type) (Hash()(value));
        }

        bool equality_check(const V& lhs, const V& rhs) const noexcept{
            return Equal()(lhs, rhs);
        }

        /* ---------------------------- search and insert operations ------------------------------ */

        index_type find_existing_index (const V& value, hash_type hash, hash_type modded_hash) const noexcept{
            V* ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V);
            HT_FIND_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                if(equality_check(ht_value_table[index], value)){
                    return index;
                }
            HT_FIND_INDEX_END(this->m_table_size, -1)
        }

        V* find_existing_ptr (const V& value, hash_type hash, hash_type modded_hash) const noexcept{
            V* ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V);
            HT_FIND_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                V* ptr = &(ht_value_table[index]);
                if(equality_check(*ptr, value)){
                    return ptr;
                }
            HT_FIND_INDEX_END(this->m_table_size, nullptr)
        }

        index_type find_free_index (const V& value, hash_type hash, hash_type modded_hash) const noexcept{
            V* ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V);
            HT_FIND_FREE_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                if(equality_check(ht_value_table[index], value)){
                    return -1;
                }
            HT_FIND_FREE_INDEX_END(this->m_table_size)
        }

        index_type find_existing_or_free_index (const V& value, hash_type hash, hash_type modded_hash) const noexcept{
            V* ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, V);
            HT_FIND_FREE_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                if(equality_check(ht_value_table[index], value)){
                    return index;
                }
            HT_FIND_FREE_INDEX_END(this->m_table_size)
        }

    };


    /* --------------------------------------------------------------------------------------
                                        MAP - DIRECT TABLE
       -------------------------------------------------------------------------------------- */

    template<
        class K,
        class V,
        class KvpAdapter = StdPairKvpAdapter<K, V>,
        class Hash = std::hash<K>,
        class EqualKey = std::equal_to<K>,
        class EqualValue = std::equal_to<V>,
        class Allocator = std::allocator<char>
    >
    class hash_table_map : public hash_table_container<typename KvpAdapter::pair_type, Allocator>{
        using BaseClass = hash_table_container<typename KvpAdapter::pair_type, Allocator>;
    public:
        using allocator = Allocator;
        using element_type = typename BaseClass::element_type;
        using key_type = K;
        using value_type = V;
        using pair_type = typename KvpAdapter::pair_type;
        using hash_function = Hash;
        using key_equality_function = EqualKey;
        using value_equality_function = EqualValue;
        using kvp_adapter = KvpAdapter;
        using iterator = typename BaseClass::iterator;
        using const_iterator = typename BaseClass::const_iterator;
        using reverse_iterator = typename BaseClass::reverse_iterator;
        using const_reverse_iterator = typename BaseClass::const_reverse_iterator;

        /* ------------------------- boilerplate ---------------------------- */

        explicit hash_table_map(size_t capacity=0, Allocator&& alloc=Allocator()) : BaseClass(capacity, std::move(alloc)) {}
        explicit hash_table_map(size_t capacity, const Allocator& alloc) : BaseClass(capacity, alloc) {}
        hash_table_map(const hash_table_map& src) : BaseClass(src) {}
        hash_table_map(hash_table_map&& src) noexcept : BaseClass(std::move(src)) {}
        hash_table_map& operator=(const hash_table_map& src){return static_cast<hash_table_map&>(BaseClass::operator=(src));}
        hash_table_map& operator=(hash_table_map&& src){return static_cast<hash_table_map&> (BaseClass::operator=(std::move(src)));}

        /* -------------------------- container operations interface ------------------------------- */

        pair_type& get_value(index_type index)const noexcept{
            return HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index];
        }

        index_type find_index(const K& key) const noexcept{
            hash_type hash = calculate_hash(key);
            return find_index_h(hash, key);
        }

        pair_type* find_ptr(const K& key) const noexcept{
            hash_type hash = calculate_hash(key);
            return find_ptr_h(hash, key);
        }

        // if using normal constructors for elements
        template<typename ...Elms> size_t insert_many(Elms&&... elms){
            this->expand_capacity(this->m_elements+sizeof...(Elms));
            return insert_many_impl(std::forward<Elms>(elms)...);
        };

        // if using normal constructors for elements
        template<typename ...Elms> size_t emplace_many(Elms&&... elms){
            this->expand_capacity(this->m_elements+sizeof...(Elms));
            return emplace_many_impl(std::forward<Elms>(elms)...);
        };

        // if using brace-initialization for elements
        size_t insert_many_il(std::initializer_list<pair_type> elms){
            this->expand_capacity(this->m_elements+elms.size());
            size_t inserted = 0;
            for(auto& v : elms){
                if(insert_value(v) >= 0)
                    inserted++;
            }
            return inserted;
        };

        // if using iterators for elements
        template<class InputIterator> size_t insert_many_it(InputIterator it_start, InputIterator it_end){
            size_t n_inserts = 0;
            for (; it_start != it_end; ++it_start){
                n_inserts += (insert_value(*it_start) >= 0 ? 1 : 0);
            }
            return n_inserts;
        }

        index_type insert_value(const pair_type& kvp){
            hash_type hash = calculate_hash(KvpAdapter().key(kvp));
            return insert_value_h(hash, kvp);
        }

        index_type insert_value(pair_type&& kvp){
            hash_type hash = calculate_hash(KvpAdapter().key(kvp));
            return insert_value_h(hash, std::move(kvp));
        }

        index_type insert_value(const K& key, const V& value){
            hash_type hash = calculate_hash(key);
            return insert_value_h(hash, key, value);
        }

        index_type insert_value(K&& key, const V& value){
            hash_type hash = calculate_hash(key);
            return insert_value_h(hash, std::move(key), value);
        }

        index_type insert_value(const K& key, V&& value){
            hash_type hash = calculate_hash(key);
            return insert_value_h(hash, key, std::move(value));
        }

        index_type insert_value(K&& key, V&& value){
            hash_type hash = calculate_hash(key);
            return insert_value_h(hash, std::move(key), std::move(value));
        }

        insert_result insert_or_find_value(const pair_type& kvp){
            hash_type hash = calculate_hash(KvpAdapter().key(kvp));
            return insert_or_find_value_h(hash, kvp);
        }

        insert_result insert_or_find_value(pair_type&& kvp){
            hash_type hash = calculate_hash(KvpAdapter().key(kvp));
            return insert_or_find_value_h(hash, std::move(kvp));
        }

        insert_result insert_or_find_value(const K& key, const V& value){
            hash_type hash = calculate_hash(key);
            return insert_or_find_value_h(hash, key, value);
        }

        insert_result insert_or_find_value(K&& key, const V& value){
            hash_type hash = calculate_hash(key);
            return insert_or_find_value_h(hash, std::move(key), value);
        }

        insert_result insert_or_find_value(const K& key, V&& value){
            hash_type hash = calculate_hash(key);
            return insert_or_find_value_h(hash, key, std::move(value));
        }

        insert_result insert_or_find_value(K&& key, V&& value){
            hash_type hash = calculate_hash(key);
            return insert_or_find_value_h(hash, std::move(key), std::move(value));
        }

        insert_result insert_or_replace_value(const pair_type& kvp){
            hash_type hash = calculate_hash(KvpAdapter().key(kvp));
            return insert_or_replace_value_h(hash, kvp);
        }

        insert_result insert_or_replace_value(pair_type&& kvp){
            hash_type hash = calculate_hash(KvpAdapter().key(kvp));
            return insert_or_replace_value_h(hash, std::move(kvp));
        }

        insert_result insert_or_replace_value(const K& key, const V& value){
            hash_type hash = calculate_hash(key);
            return insert_or_replace_value_h(hash, key, value);
        }

        insert_result insert_or_replace_value(K&& key, const V& value){
            hash_type hash = calculate_hash(key);
            return insert_or_replace_value_h(hash, std::move(key), value);
        }

        insert_result insert_or_replace_value(const K& key, V&& value){
            hash_type hash = calculate_hash(key);
            return insert_or_replace_value_h(hash, key, std::move(value));
        }

        insert_result insert_or_replace_value(K&& key, V&& value){
            hash_type hash = calculate_hash(key);
            return insert_or_replace_value_h(hash, std::move(key), std::move(value));
        }

        template<typename... ARGS> index_type emplace_value(const K& key, ARGS&&... args){
            hash_type hash = calculate_hash(key);
            return emplace_value_h(hash, key, std::forward<ARGS>(args)...);
        }

        template<typename... ARGS> index_type emplace_value(K&& key, ARGS&&... args){
            hash_type hash = calculate_hash(key);
            return emplace_value_h(hash, std::move(key), std::forward<ARGS>(args)...);
        }

        template<typename... ARGS> insert_result emplace_or_find_value(const K& key, ARGS&&... args){
            hash_type hash = calculate_hash(key);
            return emplace_or_find_value_h(hash, key, std::forward<ARGS>(args)...);
        }

        template<typename... ARGS> insert_result emplace_or_find_value(K&& key, ARGS&&... args){
            hash_type hash = calculate_hash(key);
            return emplace_or_find_value_h(hash, std::move(key), std::forward<ARGS>(args)...);
        }

        template<typename... ARGS> insert_result emplace_or_replace_value(const K& key, ARGS&&... args){
            hash_type hash = calculate_hash(key);
            return emplace_or_replace_value_h(hash, key, std::forward<ARGS>(args)...);
        }

        template<typename... ARGS> insert_result emplace_or_replace_value(K&& key, ARGS&&... args){
            hash_type hash = calculate_hash(key);
            return emplace_or_replace_value_h(hash, std::move(key), std::forward<ARGS>(args)...);
        }

        index_type erase_value(const K& key){
            hash_type hash = calculate_hash(key);
            return erase_value_h(hash, key);
        }

        iterator erase_value_and_get_next(const V& value){
            hash_type hash = calculate_hash(value);
            return erase_value_and_get_next_h(hash, value);
        }

        index_type find_index_h(hash_type hash, const K& key) const noexcept{
            hash_type modded_hash = this->calculate_modded_hash(hash);
            return find_existing_index(key, hash, modded_hash);
        }

        index_type find_index_h(hash_type hash, const pair_type& kvp) const noexcept{
            hash_type modded_hash = this->calculate_modded_hash(hash);
            return find_existing_index(KvpAdapter().key(kvp), hash, modded_hash);
        }

        pair_type* find_ptr_h(hash_type hash, const K& key) const noexcept{
            hash_type modded_hash = this->calculate_modded_hash(hash);
            return find_existing_ptr(key, hash, modded_hash);
        }

        index_type insert_value_h(hash_type hash, const pair_type& kvp){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(KvpAdapter().key(kvp), hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(kvp);
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        index_type insert_value_h(hash_type hash, pair_type&& kvp){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(KvpAdapter().key(kvp), hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(std::move(kvp));
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        index_type insert_value_h(hash_type hash, const K& key, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(key, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(key, value);
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        index_type insert_value_h(hash_type hash, K&& key, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(key, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(std::move(key), value);
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        index_type insert_value_h(hash_type hash, const K& key, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(key, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(key, std::move(value));
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        index_type insert_value_h(hash_type hash, K&& key, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(key, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(std::move(key), std::move(value));
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        insert_result insert_or_find_value_h(hash_type hash, const pair_type& kvp){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(KvpAdapter().key(kvp), hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(kvp);
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_find_value_h(hash_type hash, pair_type&& kvp){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(KvpAdapter().key(kvp), hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(std::move(kvp));
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_find_value_h(hash_type hash, const K& key, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(key, value);
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_find_value_h(hash_type hash, K&& key, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(std::move(key), value);
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_find_value_h(hash_type hash, const K& key, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(key, std::move(value));
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_find_value_h(hash_type hash, K&& key, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(std::move(key), std::move(value));
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, const pair_type& kvp){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(KvpAdapter().key(kvp), hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]) = KvpAdapter().value(kvp);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(kvp);
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, pair_type&& kvp){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(KvpAdapter().key(kvp), hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]) = std::move(KvpAdapter().value(kvp));
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(std::move(kvp));
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, const K& key, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]) = value;
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(key, value);
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, K&& key, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]) = value;
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(std::move(key), value);
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, const K& key, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]) = std::move(value);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(key, std::move(value));
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, K&& key, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]) = std::move(value);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]))) pair_type(std::move(key), std::move(value));
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        template<typename... ARGS>
        index_type emplace_value_h(hash_type hash, const K& key, ARGS&&... args){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(key, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(KvpAdapter().key(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index])))) K(key);
                ::new (static_cast<void*>(&(KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index])))) V(std::forward<ARGS>(args)...);
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        template<typename... ARGS>
        index_type emplace_value_h(hash_type hash, K&& key, ARGS&&... args){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(key, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(KvpAdapter().key(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index])))) K(std::move(key));
                ::new (static_cast<void*>(&(KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index])))) V(std::forward<ARGS>(args)...);
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        template<typename... ARGS>
        insert_result emplace_or_find_value_h(hash_type hash, const K& key, ARGS&&... args){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(KvpAdapter().key(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index])))) K(key);
                ::new (static_cast<void*>(&(KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index])))) V(std::forward<ARGS>(args)...);
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        template<typename... ARGS>
        insert_result emplace_or_find_value_h(hash_type hash, K&& key, ARGS&&... args){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(KvpAdapter().key(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index])))) K(std::move(key));
                ::new (static_cast<void*>(&(KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index])))) V(std::forward<ARGS>(args)...);
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        template<typename... ARGS>
        insert_result emplace_or_replace_value_h(hash_type hash, const K& key, ARGS&&... args){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]) = V(std::forward<ARGS>(args)...);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(KvpAdapter().key(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index])))) K(key);
                ::new (static_cast<void*>(&(KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index])))) V(std::forward<ARGS>(args)...);
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        template<typename... ARGS>
        insert_result emplace_or_replace_value_h(hash_type hash, K&& key, ARGS&&... args){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]) = V(std::forward<ARGS>(args)...);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ::new (static_cast<void*>(&(KvpAdapter().key(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index])))) K(std::move(key));
                ::new (static_cast<void*>(&(KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index])))) V(std::forward<ARGS>(args)...);
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        index_type erase_value_h(hash_type hash, const K& key){
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_index(key, hash, modded_hash);
            if(index >= 0){
                HT_DELETE_ENTRY(index, this->m_hash_table, this->m_table_size)
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index].~pair_type();
                this->m_elements--;
                this->m_elements_to_expand++;
            }
            return index;
        }

        iterator erase_value_and_get_next_h(hash_type hash, const K& key){
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_index(key, hash, modded_hash);
            if(index >= 0){
                HT_DELETE_ENTRY(index, this->m_hash_table, this->m_table_size)
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index].~pair_type();
                this->m_elements--;
                this->m_elements_to_expand++;
                return iterator(&(HT_GET_METADATA_TABLE(this->m_hash_table)[index]), &(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[index]), nullptr);
            } else {
                return this->end();
            }
        }

        size_t merge_from(const hash_table_map& source, OverlappingPolicy merge_policy=OverlappingPolicy::ignore_duplicates){
            this->expand_capacity(this->m_elements + source.m_elements);
            size_t result = 0;
            switch(merge_policy){
                case OverlappingPolicy::ignore_duplicates:{
                    HT_GET_TABLES(source.m_hash_table, source.m_table_size, pair_type, sizeof(pair_type))
                    for(size_t index=0; index < source.m_table_size; index++){
                        if(HT_VALUE_VALID(ht_metadata_table[index])){
                            hash_type hash = ht_hashes_table[index];
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type new_index = find_free_index(KvpAdapter().key(ht_values_table[index]), hash, modded_hash);
                            if(new_index >= 0){
                                HT_INSERT_ENTRY(hash, modded_hash, new_index, this->m_hash_table, this->m_table_size)
                                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[new_index]))) pair_type(ht_values_table[index]);
                                this->m_elements++;
                                this->m_elements_to_expand--;
                                result++;
                            }
                        }
                    }
                } break;
                case OverlappingPolicy::replace_duplicates:{
                    HT_GET_TABLES(source.m_hash_table, source.m_table_size, pair_type, sizeof(pair_type))
                    for(size_t index=0; index < source.m_table_size; index++){
                        if(HT_VALUE_VALID(ht_metadata_table[index])){
                            hash_type hash = ht_hashes_table[index];
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type new_index = find_existing_or_free_index(KvpAdapter().key(ht_values_table[index]), hash, modded_hash);
                            if(new_index >= 0){
                                if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[new_index])){
                                    HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[new_index] = ht_values_table[index];
                                } else {
                                    HT_INSERT_ENTRY(hash, modded_hash, new_index, this->m_hash_table, this->m_table_size)
                                    ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[new_index]))) pair_type(ht_values_table[index]);
                                    this->m_elements++;
                                    this->m_elements_to_expand--;
                                }
                                result++;
                            }
                        }
                    }
                } break;
                default:
                    break;
            }
            return result;
        }

        size_t merge_from(hash_table_map&& source, OverlappingPolicy merge_policy=OverlappingPolicy::ignore_duplicates){
            this->expand_capacity(this->m_elements + source.m_elements);
            size_t result = 0;
            switch(merge_policy){
                case OverlappingPolicy::ignore_duplicates:{
                    HT_GET_TABLES(source.m_hash_table, source.m_table_size, pair_type, sizeof(pair_type))
                    for(size_t index=0; index < source.m_table_size; index++){
                        if(HT_VALUE_VALID(ht_metadata_table[index])){
                            hash_type hash = ht_hashes_table[index];
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type new_index = find_free_index(KvpAdapter().key(ht_values_table[index]), hash, modded_hash);
                            if(new_index >= 0){
                                HT_INSERT_ENTRY(hash, modded_hash, new_index, this->m_hash_table, this->m_table_size)
                                ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[new_index]))) pair_type(std::move(ht_values_table[index]));
                                this->m_elements++;
                                this->m_elements_to_expand--;
                                result++;
                            }
                        }
                    }
                } break;
                case OverlappingPolicy::replace_duplicates:{
                    HT_GET_TABLES(source.m_hash_table, source.m_table_size, pair_type, sizeof(pair_type))
                    for(size_t index=0; index < source.m_table_size; index++){
                        if(HT_VALUE_VALID(ht_metadata_table[index])){
                            hash_type hash = ht_hashes_table[index];
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type new_index = find_existing_or_free_index(KvpAdapter().key(ht_values_table[index]), hash, modded_hash);
                            if(new_index >= 0){
                                if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[new_index])){
                                    HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[new_index] = std::move(ht_values_table[index]);
                                } else {
                                    HT_INSERT_ENTRY(hash, modded_hash, new_index, this->m_hash_table, this->m_table_size)
                                    ::new (static_cast<void*>(&(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type)[new_index]))) pair_type(std::move(ht_values_table[index]));
                                    this->m_elements++;
                                    this->m_elements_to_expand--;
                                }
                                result++;
                            }
                        }
                    }
                } break;
                default:
                    break;
            }
            source.clear();
            return result;
        }

        bool equals(const hash_table_map& other) const noexcept{
            if(this->m_elements != other.m_elements)
                return false;
            if(this->m_table_size < other.m_table_size){
                HT_GET_TABLES(this->m_hash_table, this->m_table_size, pair_type, sizeof(pair_type))
                for(size_t index=0; index < this->m_table_size; index++){
                    if(HT_VALUE_VALID(ht_metadata_table[index])){
                        pair_type* kvp_ptr = other.find_ptr_h(ht_hashes_table[index], KvpAdapter().key(ht_values_table[index]));
                        if(kvp_ptr == nullptr || !value_equality_check(*kvp_ptr, KvpAdapter().value(ht_values_table[index]))){
                            return false;
                        }
                    }
                }
                return true;
            } else {
                HT_GET_TABLES(other.m_hash_table, other.m_table_size, pair_type, sizeof(pair_type))
                for(size_t index=0; index < other.m_table_size; index++){
                    if(HT_VALUE_VALID(ht_metadata_table[index])){
                        pair_type* kvp_ptr = this->find_ptr_h(ht_hashes_table[index], KvpAdapter().key(ht_values_table[index]));
                        if(kvp_ptr == nullptr || !value_equality_check(*kvp_ptr, KvpAdapter().value(ht_values_table[index]))){
                            return false;
                        }
                    }
                }
                return true;
            }
        }

        template<typename K2, typename V2, typename KvpAdapter2, typename Hash2, typename EqualKey2, typename EqualValue2, typename Alloc2>
        friend bool operator==(const hash_table_map<K2, V2, KvpAdapter2, Hash2, EqualKey2, EqualValue2, Alloc2>& lhs, const hash_table_map<K2, V2, KvpAdapter2, Hash2, EqualKey2, EqualValue2, Alloc2>& rhs);

        template<typename K2, typename V2, typename KvpAdapter2, typename Hash2, typename EqualKey2, typename EqualValue2, typename Alloc2>
        friend bool operator!=(const hash_table_map<K2, V2, KvpAdapter2, Hash2, EqualKey2, EqualValue2, Alloc2>& lhs, const hash_table_map<K2, V2, KvpAdapter2, Hash2, EqualKey2, EqualValue2, Alloc2>& rhs);

        template<typename F=no_filter<pair_type>>
        hash_table_map copy(F filter=F(), CopyPolicy copy_policy = CopyPolicy::keep_source_capacity) const{
            hash_table_map result(0, static_cast<const Allocator&>(*this));
            this->copy_into_and_replace(result, std::forward<F>(filter), copy_policy);
            return result;
        }

    protected:

        size_t insert_many_impl(){return 0;};
        template<typename H, typename ...Elms> size_t insert_many_impl(H &&h, Elms&&... elms){
            return (insert_value(std::forward<H>(h)) >= 0) + insert_many_impl(std::forward<Elms>(elms)...);
        };

        size_t emplace_many_impl(){return 0;};
        template<typename H, typename ...Elms> size_t emplace_many_impl(H &&h, Elms&&... elms){
            return (emplace_value(std::forward<H>(h)) >= 0) + emplace_many_impl(std::forward<Elms>(elms)...);
        };

        hash_type calculate_hash (const K& key) const noexcept{
            return (hash_type) (Hash()(key));
        }

        bool key_equality_check(const pair_type& lhs, const K& rhs) const noexcept{
            return EqualKey()(KvpAdapter().key(lhs), rhs);
        }

        bool value_equality_check(const pair_type& lhs, const V& rhs) const noexcept{
            return EqualValue()(KvpAdapter().value(lhs), rhs);
        }

        /* ---------------------------- search and insert operations ------------------------------ */

        index_type find_existing_index (const K& key, hash_type hash, hash_type modded_hash) const noexcept{
            pair_type* ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type);
            HT_FIND_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                if(key_equality_check(ht_value_table[index], key)){
                    return index;
                }
            HT_FIND_INDEX_END(this->m_table_size, -1)
        }

        pair_type* find_existing_ptr (const K& key, hash_type hash, hash_type modded_hash) const noexcept{
            pair_type* ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type);
            HT_FIND_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                pair_type* ptr = &(ht_value_table[index]);
                if(key_equality_check(*ptr, key)){
                    return ptr;
                }
            HT_FIND_INDEX_END(this->m_table_size, nullptr)
        }

        index_type find_free_index (const K& key, hash_type hash, hash_type modded_hash) const noexcept{
            pair_type* ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type);
            HT_FIND_FREE_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                if(key_equality_check(ht_value_table[index], key)){
                    return -1;
                }
            HT_FIND_FREE_INDEX_END(this->m_table_size)
        }

        index_type find_existing_or_free_index (const K& key, hash_type hash, hash_type modded_hash) const noexcept{
            pair_type* ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, pair_type);
            HT_FIND_FREE_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                if(key_equality_check(ht_value_table[index], key)){
                    return index;
                }
            HT_FIND_FREE_INDEX_END(this->m_table_size)
        }
    };


    /* --------------------------------------------------------------------------------------
                                        LIST TABLES
       -------------------------------------------------------------------------------------- */

    template<class V>
    struct ListNode{
        ListNode() : prev(nullptr), next(nullptr) {}
        V value;
        ListNode<V> *prev, *next;
    };


    template<
        class V,
        class Hash = std::hash<V>,
        class Allocator = std::allocator<char>
    >
    class hash_table_list_container : public Allocator{
    public:
        const float minimum_table_size = 8;
        const float max_load_factor = 0.8;
        using element_type = V;

        /* ------------------------- constructors ---------------------------- */

        explicit hash_table_list_container(size_t capacity=0, Allocator&& alloc=Allocator()) : Allocator(std::move(alloc)) {
            if(capacity > 0){
                set_initial_capacity(capacity);
            } else {
                m_hash_table = nullptr;
                m_list_head = nullptr;
                m_list_tail = nullptr;
                m_table_size = 0;
                m_elements = 0;
                m_elements_to_expand = 0;
            }
        }

        explicit hash_table_list_container(size_t capacity, const Allocator& alloc) : Allocator(alloc) {
            if(capacity > 0){
                set_initial_capacity(capacity);
            } else {
                m_hash_table = nullptr;
                m_list_head = nullptr;
                m_list_tail = nullptr;
                m_table_size = 0;
                m_elements = 0;
                m_elements_to_expand = 0;
            }
        }

        ~hash_table_list_container(){
            if(m_hash_table != nullptr){
                if(m_list_head != nullptr)
                    delete_elements();
                mem_free(m_hash_table, m_table_size);
            }
        }

        hash_table_list_container(const hash_table_list_container& src){
            if(src.m_elements == 0){
                m_hash_table = nullptr;
                m_list_head = nullptr;
                m_list_tail = nullptr;
                m_table_size = 0;
                m_elements = 0;
                m_elements_to_expand = 0;
            } else {
                set_initial_capacity(src.m_elements);
                if(src.m_list_head != nullptr)
                    copy_elements(src.m_list_head, src.m_table_size);
            }
        }

        hash_table_list_container(hash_table_list_container&& src) noexcept{
            if (std::allocator_traits<Allocator>::propagate_on_container_move_assignment::value){
                static_cast<Allocator&>(*this) = std::move(static_cast<Allocator&>(src));
            }
            m_hash_table = src.m_hash_table;
            m_list_head = src.m_list_head;
            m_list_tail = src.m_list_tail;
            m_table_size = src.m_table_size;
            m_elements = src.m_elements;
            m_elements_to_expand = src.m_elements_to_expand;
            src.m_hash_table = nullptr;
            src.m_list_head = nullptr;
            src.m_list_tail = nullptr;
            src.m_table_size = 0;
            src.m_elements = 0;
            src.m_elements_to_expand = 0;
        }

        hash_table_list_container& operator=(const hash_table_list_container& src){
            if(&src != this){
                if(m_hash_table != nullptr){
                    clear();
                    expand_capacity(src.m_elements);
                } else {
                    if(src.m_elements > 0)
                        set_initial_capacity(src.m_elements);
                }
                if(src.m_elements > 0)
                    copy_elements(src.m_list_head, src.m_table_size);
            }
            return *this;
        }

        hash_table_list_container& operator=(hash_table_list_container&& src){
            if(&src != this){
                if(m_hash_table != nullptr){
                    if(m_list_head != nullptr)
                        delete_elements();
                    mem_free(m_hash_table, m_table_size);
                }
                if (std::allocator_traits<Allocator>::propagate_on_container_move_assignment::value){
                    static_cast<Allocator&>(*this) = std::move(static_cast<Allocator&>(src));
                }
                m_hash_table = src.m_hash_table;
                m_list_head = src.m_list_head;
                m_list_tail = src.m_list_tail;
                m_table_size = src.m_table_size;
                m_elements = src.m_elements;
                m_elements_to_expand = src.m_elements_to_expand;
                src.m_hash_table = nullptr;
                src.m_list_head = nullptr;
                src.m_list_tail = nullptr;
                src.m_table_size = 0;
                src.m_elements = 0;
                src.m_elements_to_expand = 0;
            }
            return *this;
        }

        /* ------------------------ common methods ------------------------- */

        void swap(hash_table_list_container& other) noexcept{
            if (std::allocator_traits<Allocator>::propagate_on_container_swap::value){
                std::swap(static_cast<Allocator&>(*this), static_cast<Allocator&>(other));
            }
            std::swap(m_hash_table, other.m_hash_table);
            std::swap(m_list_head, other.m_list_head);
            std::swap(m_list_tail, other.m_list_tail);
            std::swap(m_table_size, other.m_table_size);
            std::swap(m_elements, other.m_elements);
            std::swap(m_elements_to_expand, other.m_elements_to_expand);
        }

        void clear(){
            delete_elements();
            invalidate_elements(m_hash_table, m_table_size);
            m_elements_to_expand += m_elements;
            m_elements = 0;
        }

        size_t size() const noexcept {return m_elements;}

        hash_type get_hash_of(index_type index) const noexcept{
            return HT_GET_HASHSES_TABLE(m_hash_table, m_table_size)[index];
        }

        template<typename F>
        void iterate(F func) const{
            ListNode<V>* head = m_list_head;
            while(head != nullptr){
                hash_type hash = this->calculate_hash(head->value);
                func(hash, head->value);
                head = head->next;
            }
        }

        template<typename F>
        void self_filter(F filter){
            if(this->m_elements > 0){
                HT_GET_TABLES(this->m_hash_table, this->m_table_size, ListNode<V>*, sizeof(ListNode<V>*))
                for(size_t index=0; index < this->m_table_size; index++){
                    if(HT_VALUE_VALID(ht_metadata_table[index])){
                        if(!filter(ht_hashes_table[index], ht_values_table[index]->value)){
                            remove_node(ht_values_table[index]);
                            m_elements--;
                            m_elements_to_expand++;
                            HT_DELETE_ENTRY(index, m_hash_table, m_table_size)
                        }
                    }
                }
            }
        }

        template<typename F=no_filter<V>>
        void copy_into_and_replace(hash_table_list_container& target, F filter=F(), CopyPolicy copy_policy = CopyPolicy::keep_target_capacity) const{
            target.clear();
            switch(copy_policy){
            case CopyPolicy::duplicate_source:
                target.change_table_size(this->m_table_size);
                break;
            case CopyPolicy::minimal_capacity:
                target.set_capacity(0);
                break;
            case CopyPolicy::keep_source_capacity:
                target.set_capacity(this->m_elements);
                break;
            case CopyPolicy::keep_target_capacity:
                break;
            default:
                break;
            }
            if(this->m_elements > 0){
                ListNode<V>* head = m_list_head;
                while(head != nullptr){
                    target.check_and_expand_full_capacity();
                    hash_type hash = target.calculate_hash(head->value);
                    hash_type modded_hash = target.calculate_modded_hash(hash);
                    if(filter(hash, head->value)){
                        index_type index = target.find_guaranteed_free_index(modded_hash);
                        HT_INSERT_ENTRY(hash, modded_hash, index, target.m_hash_table, target.m_table_size)
                        ListNode<V>* node = target.copy_node(head);
                        HT_GET_VALUES_TABLE(target.m_hash_table, target.m_table_size, ListNode<V>*)[index] = node;
                        target.m_elements++;
                        target.m_elements_to_expand--;
                    }
                    head = head->next;
                }
            }
        }

        /* ------------------------ capacity and rehashing management interface ------------------------- */

        /* get the total available capacity */
        size_t get_capacity(){
            return m_elements + m_elements_to_expand;
        }

        /* Forces rehashing, and optionally shrinking, the table. */
        void rehash_table(bool shrink_capacity=true){
            if(shrink_capacity){
                set_capacity(0, true);
            } else {
                if(m_hash_table != nullptr){
                    recalculate_table(m_table_size);
                }
            }
        }

        /* Try to set the specified capacity, and optionally, force rehashing the table. */
        /* Returns true if a rehashing took place. */
        bool set_capacity(size_t capacity, bool force_rehash=false){
            size_t new_table_size = calculate_minimum_table_size(capacity);
            if(m_table_size != new_table_size){
                bool recalculated_table = change_table_size(new_table_size);
                if(!recalculated_table && force_rehash){
                    if(m_hash_table != nullptr){
                        recalculate_table(m_table_size);
                    }
                    recalculated_table = true;
                }
                return recalculated_table;
            } else {
                if(force_rehash){
                    if(m_hash_table != nullptr){
                        recalculate_table(m_table_size);
                    }
                    return true;
                }
                return false;
            }
        }

        /* If the current capacity is sufficient to insert an element, return false. */
        /* Otherwise, expand the capacity and return true */
        bool check_and_expand_full_capacity(){
            if(m_elements_to_expand == 0){
                expand_capacity(m_elements + 1);
                return true;
            } else {
                return false;
            }
        }

        /* Try to set the specified capacity, but the current capacity may only expand. */
        bool expand_capacity(size_t capacity){
            size_t new_table_size = calculate_minimum_table_size(capacity);
            if(m_table_size < new_table_size){
                return change_table_size(new_table_size);
            } else {
                return false;
            }
        }

        /* ---------------------------- iterator interface ------------------------------ */

        struct iterator;
        friend struct iterator;
        struct const_iterator;
        friend struct const_iterator;

        struct reverse_iterator;
        friend struct reverse_iterator;
        struct const_reverse_iterator;
        friend struct const_reverse_iterator;

        iterator begin() noexcept{ return iterator(m_list_head);}
        const_iterator begin()const noexcept{ return const_iterator(m_list_head);}
        const_iterator cbegin()const noexcept{ return const_iterator(m_list_head);}

        reverse_iterator rbegin() noexcept{ return reverse_iterator(m_list_tail);}
        const_reverse_iterator rbegin()const noexcept{ return const_reverse_iterator(m_list_tail);}
        const_reverse_iterator crbegin()const noexcept{ return const_reverse_iterator(m_list_tail);}

        iterator end() noexcept{ return iterator(nullptr);}
        const_iterator end() const noexcept{ return const_iterator(nullptr);}
        const_iterator cend() const noexcept{ return const_iterator(nullptr);}

        reverse_iterator rend() noexcept{ return reverse_iterator(nullptr);}
        const_reverse_iterator rend() const noexcept{ return const_reverse_iterator(nullptr);}
        const_reverse_iterator crend() const noexcept{ return const_reverse_iterator(nullptr);}

        iterator at_index(index_type index) noexcept{ return iterator(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, ListNode<V>*)[index]);}
        const_iterator at_index(index_type index) const noexcept{ return const_iterator(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, ListNode<V>*)[index]);}

        reverse_iterator at_index_r(index_type index) noexcept{ return reverse_iterator(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, ListNode<V>*)[index]);}
        const_reverse_iterator at_index_r(index_type index) const noexcept{ return const_reverse_iterator(HT_GET_VALUES_TABLE(m_hash_table, m_table_size, ListNode<V>*)[index]);}

    protected:

        hash_type calculate_hash (const V& value) const noexcept{
            return (hash_type) (Hash()(value));
        }

        hash_type calculate_modded_hash (hash_type hash) const noexcept{
            return (hash_type)(hash % m_table_size);
        }

        index_type find_guaranteed_free_index(hash_type modded_hash) const noexcept{
            HT_GET_GUARANTEED_FREE_INDEX(modded_hash, m_hash_table, m_table_size)
        }

        /* ----------------------------- memory allocation --------------------------- */

        void* mem_alloc(size_t size) {
            return Allocator::allocate(size);
        }

        void mem_free(void* table, size_t size) noexcept{
            Allocator::deallocate(static_cast<char*>(table), size);
        }

        /* ----------------------------- table operations helpers --------------------------- */

        size_t calculate_table_size(size_t capacity) const noexcept{
            if(capacity < minimum_table_size){
                return minimum_table_size;
            } else {
                size_t result = 0;
                capacity = capacity - 1;
                while(capacity > 0){
                    capacity = capacity >> 1;
                    result++;
                }
                return 1 << result;
            }
        }

        size_t calculate_minimum_table_size(size_t capacity) const noexcept{
            if(capacity < m_elements)
                capacity = m_elements;
            size_t table_size = calculate_table_size(capacity);
            while(capacity > (table_size * max_load_factor))
                table_size = table_size << 1;
            return table_size;
        }

        void set_initial_capacity(size_t capacity){
            size_t table_size = calculate_table_size(capacity);
            while(capacity > (table_size * max_load_factor))
                table_size = table_size << 1;
            m_hash_table = allocate_table(table_size);
            m_table_size = table_size;
            m_list_head = nullptr;
            m_list_tail = nullptr;
            m_elements = 0;
            m_elements_to_expand = table_size * max_load_factor;
        }

        void set_initial_table_size(size_t table_size){
            m_hash_table = allocate_table(table_size);
            m_table_size = table_size;
            m_list_head = nullptr;
            m_list_tail = nullptr;
            m_elements = 0;
            m_elements_to_expand = table_size * max_load_factor;
        }

        void* allocate_table(size_t table_size){
            if(table_size == 0){
                return nullptr;
            } else {
                size_t total_table_size = HT_TABLE_SIZE(table_size, sizeof(V));
                void* hash_table = mem_alloc(total_table_size);
                memset(hash_table, 0, total_table_size); // for debugging purposes
                memset(hash_table, 0, HT_METADATA_SIZE(table_size));
                memset(HT_GET_PADDING_TABLE(hash_table, table_size), 0xff, HT_PADDING_SIZE);
                return hash_table;
            }
        }

        bool change_table_size(size_t new_table_size){
            if(m_table_size != new_table_size){
                recalculate_table(new_table_size);
                return true;
            } else {
                return false;
            }
        }

        void recalculate_table(size_t new_table_size){
            size_t prev_table_size = m_table_size;
            void* prev_hash_table = m_hash_table;
            size_t prev_elements = m_elements;
            void* new_table = allocate_table(new_table_size);
            m_hash_table = new_table;
            m_table_size = new_table_size;
            m_elements = 0;
            m_elements_to_expand = new_table_size * max_load_factor;
            if(prev_hash_table != nullptr){
                if(prev_elements > 0){
                    move_pointers(prev_hash_table, prev_table_size);
                }
                mem_free(prev_hash_table, prev_table_size);
            }
        }

        /* --------------------------- list node operations ----------------------------- */

        void insert_node_at_end(ListNode<V>* node){
            node->next = nullptr;
            if(m_list_tail != nullptr){
                m_list_tail->next = node;
                node->prev = m_list_tail;
                m_list_tail = node;
            } else {
                node->prev = nullptr;
                m_list_head = m_list_tail = node;
            }
        }

        template<typename... ARGS>
        ListNode<V>* create_node(ARGS&&... args){
            ListNode<V> *node = static_cast<ListNode<V>*>(mem_alloc(sizeof(ListNode<V>)));
            ::new (static_cast<void*>(&(node->value))) V(std::forward<ARGS>(args)...);
            return node;
        }

        template<typename... ARGS>
        ListNode<V>* insert_node(ARGS&&... args){
            ListNode<V> *node = static_cast<ListNode<V>*>(mem_alloc(sizeof(ListNode<V>)));
            ::new (static_cast<void*>(&(node->value))) V(std::forward<ARGS>(args)...);
            insert_node_at_end(node);
            return node;
        }

        ListNode<V>* copy_node(ListNode<V>* source){
            ListNode<V> *node = static_cast<ListNode<V>*>(mem_alloc(sizeof(ListNode<V>)));
            ::new (static_cast<void*>(&(node->value))) V(source->value);
            insert_node_at_end(node);
            return node;
        }

        void detatch_node(ListNode<V>* node){
            ListNode<V>* prev_node = node->prev;
            ListNode<V>* next_node = node->next;
            if(prev_node == nullptr){
                m_list_head = next_node;
            } else {
                prev_node->next = next_node;
            }
            if(next_node == nullptr){
                m_list_tail = prev_node;
            } else {
                next_node->prev = prev_node;
            }
        }

        void replace_node(ListNode<V>* node, ListNode<V>* target_node){
            ListNode<V>* prev_node = target_node->prev;
            ListNode<V>* next_node = target_node->next;
            if(prev_node == nullptr){
                m_list_head = node;
            } else {
                prev_node->next = node;
            }
            if(next_node == nullptr){
                m_list_tail = node;
            } else {
                next_node->prev = node;
            }
            node->prev = prev_node;
            node->next = next_node;
        }

        void remove_node(ListNode<V>* node){
            detatch_node(node);
            node->value.~V();
            mem_free(node, sizeof(ListNode<V>));
        }

        /* --------------------------- bulk element operations ----------------------------- */

        void move_pointers(void* source_hash_table, size_t source_table_size){
            HT_GET_TABLES(source_hash_table, source_table_size, ListNode<V>*, sizeof(ListNode<V>*))
            for(size_t index=0; index < source_table_size; index++){
                if(HT_VALUE_VALID(ht_metadata_table[index])){
                    hash_type hash = ht_hashes_table[index];
                    hash_type modded_hash = calculate_modded_hash(hash);
                    index_type new_index = find_guaranteed_free_index(modded_hash);
                    HT_INSERT_ENTRY(hash, modded_hash, new_index, m_hash_table, m_table_size)
                    HT_GET_VALUES_TABLE(m_hash_table, m_table_size, ListNode<V>*)[new_index] = ht_values_table[index];
                    m_elements++;
                    m_elements_to_expand--;
                }
            }
        }

        void copy_elements(ListNode<V>* source_list_head, size_t source_table_size){
            while(source_list_head != nullptr){
                hash_type hash = calculate_hash(source_list_head->value);
                hash_type modded_hash = calculate_modded_hash(hash);
                index_type index = find_guaranteed_free_index(modded_hash);
                HT_INSERT_ENTRY(hash, modded_hash, index, m_hash_table, m_table_size)
                ListNode<V>* node = copy_node(source_list_head);
                HT_GET_VALUES_TABLE(m_hash_table, m_table_size, ListNode<V>*)[index] = node;
                m_elements++;
                m_elements_to_expand--;
                source_list_head = source_list_head->next;
            }
        }

        template<typename F>
        void copy_elements(ListNode<V>* source_list_head, size_t source_table_size, F filter){
            while(source_list_head != nullptr){
                hash_type hash = calculate_hash(source_list_head->value);
                hash_type modded_hash = calculate_modded_hash(hash);
                if(filter(hash, source_list_head->value)){
                    index_type index = find_guaranteed_free_index(modded_hash);
                    HT_INSERT_ENTRY(hash, modded_hash, index, m_hash_table, m_table_size)
                    ListNode<V>* node = copy_node(source_list_head);
                    HT_GET_VALUES_TABLE(m_hash_table, m_table_size, ListNode<V>*)[index] = node;
                    m_elements++;
                    m_elements_to_expand--;
                }
                source_list_head = source_list_head->next;
            }
        }

        void move_elements(ListNode<V>* source_list_head, size_t source_table_size){
            m_list_head = source_list_head;
            while(source_list_head != nullptr){
                hash_type hash = calculate_hash(source_list_head->value);
                hash_type modded_hash = calculate_modded_hash(hash);
                index_type index = find_guaranteed_free_index(modded_hash);
                HT_INSERT_ENTRY(hash, modded_hash, index, m_hash_table, m_table_size)
                HT_GET_VALUES_TABLE(m_hash_table, m_table_size, ListNode<V>*)[index] = source_list_head;
                m_list_tail = source_list_head;
                m_elements++;
                m_elements_to_expand--;
                source_list_head = source_list_head->next;
            }
        }

        template<typename F>
        void move_elements(ListNode<V>* source_list_head, size_t source_table_size, F filter){
            m_list_head = source_list_head;
            while(source_list_head != nullptr){
                hash_type hash = calculate_hash(source_list_head->value);
                hash_type modded_hash = calculate_modded_hash(hash);
                if(filter(hash, source_list_head->value)){
                    index_type index = find_guaranteed_free_index(modded_hash);
                    HT_INSERT_ENTRY(hash, modded_hash, index, m_hash_table, m_table_size)
                    HT_GET_VALUES_TABLE(m_hash_table, m_table_size, ListNode<V>*)[index] = source_list_head;
                    m_list_tail = source_list_head;
                    m_elements++;
                    m_elements_to_expand--;
                }
                source_list_head = source_list_head->next;
            }
        }

        void delete_elements(){
            ListNode<V> *node = m_list_head;
            while(node != nullptr){
                ListNode<V> *next_node = node->next;
                node->value.~V();
                mem_free(node, sizeof(ListNode<V>));
                node = next_node;
            }
            m_list_head = m_list_tail = nullptr;
        }

        void invalidate_elements(void* hash_table, size_t table_size) noexcept{
            memset(hash_table, 0, HT_METADATA_SIZE(table_size));
            memset(HT_GET_VALUES_TABLE(hash_table, table_size, ListNode<V>*), 0, HT_VALUES_SIZE(table_size, sizeof(V)));
        }

        void* m_hash_table;
        ListNode<V> *m_list_head, *m_list_tail;
        size_t m_table_size;
        size_t m_elements;
        size_t m_elements_to_expand;
    };

    template<class V, class Hash, class Allocator>
    struct hash_table_list_container<V, Hash, Allocator>::iterator{
        typedef std::forward_iterator_tag iterator_category;
        typedef V value_type;
        typedef V* pointer;
        typedef V& reference;
        iterator(ListNode<V> *node) noexcept : node(node) {}
        ListNode<V> *node;
        bool operator==(const iterator& it) const noexcept {return node == it.node;}
        bool operator!=(const iterator& it) const noexcept {return node != it.node;}
        V& operator*() const noexcept {return node->value;}
        V* operator->() const noexcept {return &(node->value);}
        operator bool() const noexcept {return node != nullptr;}
        iterator& operator++() noexcept {node = node->next; return *this;}
        iterator& operator++(int) noexcept {node = node->next; return *this;}
    };

    template<class V, class Hash, class Allocator>
    struct hash_table_list_container<V, Hash, Allocator>::const_iterator{
        typedef std::forward_iterator_tag iterator_category;
        typedef V value_type;
        typedef const V* pointer;
        typedef const V& reference;
        const_iterator(ListNode<V> *node) noexcept : node(node){}
        ListNode<V> *node;
        bool operator==(const const_iterator& it) const noexcept {return node == it.node;}
        bool operator!=(const const_iterator& it) const noexcept {return node != it.node;}
        const V& operator*() const noexcept {return node->value;}
        const V* operator->() const noexcept {return &(node->value);}
        operator bool()const noexcept {return node != nullptr;}
        const_iterator& operator++() noexcept {node = node->next; return *this;}
        const_iterator& operator++(int) noexcept {node = node->next;return *this;}
    };

    template<class V, class Hash, class Allocator>
    struct hash_table_list_container<V, Hash, Allocator>::reverse_iterator{
        typedef std::forward_iterator_tag iterator_category;
        typedef V value_type;
        typedef V* pointer;
        typedef V& reference;
        reverse_iterator(ListNode<V> *node) noexcept : node(node) {}
        ListNode<V> *node;
        bool operator==(const reverse_iterator& it) const noexcept {return node == it.node;}
        bool operator!=(const reverse_iterator& it) const noexcept {return node != it.node;}
        V& operator*() const noexcept {return node->value;}
        V* operator->() const noexcept {return &(node->value);}
        operator bool() const noexcept {return node != nullptr;}
        reverse_iterator& operator++() noexcept {node = node->prev; return *this;}
        reverse_iterator& operator++(int) noexcept {node = node->prev; return *this;}
    };

    template<class V, class Hash, class Allocator>
    struct hash_table_list_container<V, Hash, Allocator>::const_reverse_iterator{
        typedef std::forward_iterator_tag iterator_category;
        typedef V value_type;
        typedef const V* pointer;
        typedef const V& reference;
        const_reverse_iterator(ListNode<V> *node) noexcept : node(node){}
        ListNode<V> *node;
        bool operator==(const const_reverse_iterator& it) const noexcept {return node == it.node;}
        bool operator!=(const const_reverse_iterator& it) const noexcept {return node != it.node;}
        const V& operator*() const noexcept {return node->value;}
        const V* operator->() const noexcept {return &(node->value);}
        operator bool()const noexcept {return node != nullptr;}
        const_reverse_iterator& operator++() noexcept {node = node->prev; return *this;}
        const_reverse_iterator& operator++(int) noexcept {node = node->prev;return *this;}
    };


    /* --------------------------------------------------------------------------------------
                                        SET - LIST TABLE
       -------------------------------------------------------------------------------------- */

    template<
        class V,
        class Hash = std::hash<V>,
        class Equal = std::equal_to<V>,
        class Allocator = std::allocator<char>
    >
    class hash_table_list_set : public hash_table_list_container<V, Hash, Allocator>{
        using BaseClass = hash_table_list_container<V, Hash, Allocator>;
    public:
        using allocator = Allocator;
        using element_type = typename BaseClass::element_type;
        using value_type = V;
        using hash_function = Hash;
        using equality_function = Equal;
        using iterator = typename BaseClass::iterator;
        using const_iterator = typename BaseClass::const_iterator;
        using reverse_iterator = typename BaseClass::reverse_iterator;
        using const_reverse_iterator = typename BaseClass::const_reverse_iterator;

        /* ------------------------- boilerplate ---------------------------- */

        explicit hash_table_list_set(size_t capacity=0, Allocator&& alloc=Allocator()) : BaseClass(capacity, std::move(alloc)) {}
        explicit hash_table_list_set(size_t capacity, const Allocator& alloc) : BaseClass(capacity, alloc) {}
        hash_table_list_set(const hash_table_list_set& src) : BaseClass(src) {}
        hash_table_list_set(hash_table_list_set&& src) noexcept : BaseClass(std::move(src)) {}
        hash_table_list_set& operator=(const hash_table_list_set& src) { return static_cast<hash_table_list_set&>(BaseClass::operator=(src)); }
        hash_table_list_set& operator=(hash_table_list_set&& src) { return static_cast<hash_table_list_set&>(BaseClass::operator=(std::move(src))); }

        /* -------------------------- container operations interface ------------------------------- */

        V& get_value(index_type index)const noexcept{
            return HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index]->value;
        }

        index_type find_index(const V& value) const noexcept{
            hash_type hash = calculate_hash(value);
            return find_index_h(hash, value);
        }

        V* find_ptr(const V& value) const noexcept{
            hash_type hash = calculate_hash(value);
            return find_ptr_h(hash, value);
        }

        // if using normal constructors for elements
        template<typename ...Elms> size_t insert_many(Elms&&... elms){
            this->expand_capacity(this->m_elements+sizeof...(Elms));
            return insert_many_impl(std::forward<Elms>(elms)...);
        };

        // if using normal constructors for elements
        template<typename ...Elms> size_t emplace_many(Elms&&... elms){
            this->expand_capacity(this->m_elements+sizeof...(Elms));
            return emplace_many_impl(std::forward<Elms>(elms)...);
        };

        // if using brace-initialization for elements
        size_t insert_many_il(std::initializer_list<V> elms){
            this->expand_capacity(this->m_elements+elms.size());
            size_t inserted = 0;
            for(auto& v : elms){
                if(insert_value(v) >= 0)
                    inserted++;
            }
            return inserted;
        };

        // if using iterators for elements
        template<class InputIterator> size_t insert_many_it(InputIterator it_start, InputIterator it_end){
            size_t n_inserts = 0;
            for (; it_start != it_end; ++it_start){
                n_inserts += (insert_value(*it_start) >= 0 ? 1 : 0);
            }
            return n_inserts;
        }

        index_type insert_value(V&& value){
            hash_type hash = calculate_hash(value);
            return insert_value_h(hash, std::move(value));
        }

        index_type insert_value(const V& value){
            hash_type hash = calculate_hash(value);
            return insert_value_h(hash, value);
        }

        insert_result insert_or_find_value(V&& value){
            hash_type hash = calculate_hash(value);
            return insert_or_find_value_h(hash, std::move(value));
        }

        insert_result insert_or_find_value(const V& value){
            hash_type hash = calculate_hash(value);
            return insert_or_find_value_h(hash, value);
        }

        insert_result insert_or_replace_value(const V& value){
            hash_type hash = calculate_hash(value);
            return insert_or_replace_value_h(hash, value);
        }

        insert_result insert_or_replace_value(V&& value){
            hash_type hash = calculate_hash(value);
            return insert_or_replace_value_h(hash, std::move(value));
        }

        template<typename... ARGS> index_type emplace_value(ARGS&&... args){
            return insert_value(V(std::forward<ARGS>(args)...));
        }

        template<typename... ARGS> insert_result emplace_or_find_value(ARGS&&... args){
            return insert_or_find_value(V(std::forward<ARGS>(args)...));
        }

        template<typename... ARGS> insert_result emplace_or_replace_value(ARGS&&... args){
            ListNode<V>* node = this->create_node(std::forward<ARGS>(args)...);
            hash_type hash = calculate_hash(node->value);
            return insert_or_replace_node_h(node);
        }

        index_type erase_value(const V& value){
            hash_type hash = calculate_hash(value);
            return erase_value_h(hash, value);
        }

        iterator erase_value_and_get_next(const V& value){
            hash_type hash = calculate_hash(value);
            return erase_value_and_get_next_h(hash, value);
        }

        index_type find_index_h(hash_type hash, const V& value) const noexcept{
            hash_type modded_hash = this->calculate_modded_hash(hash);
            return find_existing_index(value, hash, modded_hash);
        }

        V* find_ptr_h(hash_type hash, const V& value) const noexcept{
            hash_type modded_hash = this->calculate_modded_hash(hash);
            return find_existing_ptr(value, hash, modded_hash);
        }

        index_type insert_value_h(hash_type hash, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(value, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<V> *node = this->insert_node(value);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        index_type insert_value_h(hash_type hash, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(value, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<V> *node = this->insert_node(std::move(value));
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        index_type insert_value_h(hash_type hash, ListNode<V> *node){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(node->value, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        insert_result insert_or_find_value_h(hash_type hash, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(value, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<V> *node = this->insert_node(value);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_find_value_h(hash_type hash, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(value, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<V> *node = this->insert_node(std::move(value));
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_find_node_h(hash_type hash, ListNode<V>* node){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(node->value, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                node->value.~V();
                this->mem_free(node, sizeof(ListNode<V>));
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                this->insert_node_at_end(node);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(value, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = value;
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<V> *node = this->insert_node(value);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(value, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index]->value = std::move(value);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<V> *node = this->insert_node(std::move(value));
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_node_h(hash_type hash, ListNode<V>* node){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(node->value, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index]->value = std::move(node->value);
                node->value.~V();
                this->mem_free(node, sizeof(ListNode<V>));
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                this->insert_node_at_end(node);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        index_type erase_value_h(hash_type hash, const V& value){
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_index(value, hash, modded_hash);
            if(index >= 0){
                HT_DELETE_ENTRY(index, this->m_hash_table, this->m_table_size)
                this->remove_node(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index]);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = nullptr;
                this->m_elements--;
                this->m_elements_to_expand++;
            }
            return index;
        }

        iterator erase_value_and_get_next_h(hash_type hash, const V& value){
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_index(value, hash, modded_hash);
            if(index >= 0){
                HT_DELETE_ENTRY(index, this->m_hash_table, this->m_table_size)
                ListNode<V>* node = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index];
                ListNode<V>* next_node = node->next;
                this->remove_node(node);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = nullptr;
                this->m_elements--;
                this->m_elements_to_expand++;
                return iterator(next_node);
            } else {
                return this->end();
            }
        }

        size_t merge_from(const hash_table_list_set& source, OverlappingPolicy merge_policy=OverlappingPolicy::ignore_duplicates){
            this->expand_capacity(this->m_elements + source.m_elements);
            size_t result = 0;
            switch(merge_policy){
                case OverlappingPolicy::ignore_duplicates:{
                    ListNode<V>* source_list_head = source.m_list_head;
                    while(source_list_head != nullptr){
                        hash_type hash = this->calculate_hash(source_list_head->value);
                        hash_type modded_hash = this->calculate_modded_hash(hash);
                        index_type index = find_free_index(source_list_head->value, hash, modded_hash);
                        if(index >= 0){
                            HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                            ListNode<V>* node = this->copy_node(source_list_head);
                            HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                            this->m_elements++;
                            this->m_elements_to_expand--;
                            result++;
                        }
                        source_list_head = source_list_head->next;
                    }
                } break;
                case OverlappingPolicy::replace_duplicates:{
                    ListNode<V>* source_list_head = source.m_list_head;
                    while(source_list_head != nullptr){
                        hash_type hash = this->calculate_hash(source_list_head->value);
                        hash_type modded_hash = this->calculate_modded_hash(hash);
                        index_type index = find_existing_or_free_index(source_list_head->value, hash, modded_hash);
                        if(index >= 0){
                            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index]->value = source_list_head->value;
                            } else {
                                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                                ListNode<V>* node = this->copy_node(source_list_head);
                                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                                this->m_elements++;
                                this->m_elements_to_expand--;
                            }
                            result++;
                        }
                        source_list_head = source_list_head->next;
                    }
                } break;
                default:
                    break;
            }
            return result;
        }

        size_t merge_from(hash_table_list_set&& source, OverlappingPolicy merge_policy=OverlappingPolicy::ignore_duplicates){
            this->expand_capacity(this->m_elements + source.m_elements);
            size_t result = 0;
            switch(merge_policy){
                case OverlappingPolicy::ignore_duplicates:{
                    ListNode<V>* source_list_head = source.m_list_head;
                    if(static_cast<Allocator&>(*this) == static_cast<Allocator&>(source)){
                        while(source_list_head != nullptr){
                            ListNode<V>* next_node = source_list_head->next;
                            hash_type hash = this->calculate_hash(source_list_head->value);
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type index = find_free_index(source_list_head->value, hash, modded_hash);
                            if(index >= 0){
                                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                                ListNode<V>* node = source_list_head;
                                source.detatch_node(node);
                                this->insert_node_at_end(node);
                                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                                this->m_elements++;
                                this->m_elements_to_expand--;
                                result++;
                            }
                            source_list_head = next_node;
                        }
                    } else {
                        while(source_list_head != nullptr){
                            ListNode<V>* next_node = source_list_head->next;
                            hash_type hash = this->calculate_hash(source_list_head->value);
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type index = find_free_index(source_list_head->value, hash, modded_hash);
                            if(index >= 0){
                                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                                ListNode<V>* node = this->insert_node(std::move(source_list_head->value));
                                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                                this->m_elements++;
                                this->m_elements_to_expand--;
                                result++;
                            }
                            source_list_head = next_node;
                        }
                    }
                } break;
                case OverlappingPolicy::replace_duplicates:{
                    ListNode<V>* source_list_head = source.m_list_head;
                    if(static_cast<Allocator&>(*this) == static_cast<Allocator&>(source)){
                        while(source_list_head != nullptr){
                            ListNode<V>* next_node = source_list_head->next;
                            hash_type hash = this->calculate_hash(source_list_head->value);
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type index = find_existing_or_free_index(source_list_head->value, hash, modded_hash);
                            if(index >= 0){
                                if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                                    ListNode<V>* target_node = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index];
                                    source.detatch_node(source_list_head);
                                    this->replace_node(source_list_head, target_node);
                                    target_node->value.~V();
                                    this->mem_free(target_node, sizeof(ListNode<V>));
                                    HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = source_list_head;
                                } else {
                                    HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                                    source.detatch_node(source_list_head);
                                    this->insert_node_at_end(source_list_head);
                                    HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = source_list_head;
                                    this->m_elements++;
                                    this->m_elements_to_expand--;
                                }
                                result++;
                            }
                            source_list_head = next_node;
                        }
                    } else {
                        while(source_list_head != nullptr){
                            ListNode<V>* next_node = source_list_head->next;
                            hash_type hash = this->calculate_hash(source_list_head->value);
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type index = find_existing_or_free_index(source_list_head->value, hash, modded_hash);
                            if(index >= 0){
                                if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                                    ListNode<V>* target_node = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index];
                                    target_node->value = std::move(source_list_head->value);
                                    HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = source_list_head;
                                } else {
                                    HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                                    ListNode<V>* node = this->insert_node(std::move(source_list_head->value));
                                    HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = node;
                                    this->m_elements++;
                                    this->m_elements_to_expand--;
                                }
                                result++;
                            }
                            source_list_head = next_node;
                        }
                    }
                } break;
                default:
                    break;
            }
            source.clear();
            return result;
        }

        bool equals(const hash_table_list_set& other) const noexcept{
            if(this->m_elements != other.m_elements)
                return false;
            if(this->m_table_size < other.m_table_size){
                HT_GET_TABLES(this->m_hash_table, this->m_table_size, ListNode<V>*, sizeof(ListNode<V>*))
                for(size_t index=0; index < this->m_table_size; index++){
                    if(HT_VALUE_VALID(ht_metadata_table[index])){
                        V* value_ptr = other.find_ptr_h(ht_hashes_table[index], ht_values_table[index]->value);
                        if(value_ptr == nullptr){
                            return false;
                        }
                    }
                }
                return true;
            } else {
                HT_GET_TABLES(other.m_hash_table, other.m_table_size, ListNode<V>*, sizeof(ListNode<V>*))
                for(size_t index=0; index < other.m_table_size; index++){
                    if(HT_VALUE_VALID(ht_metadata_table[index])){
                        V* value_ptr = this->find_ptr_h(ht_hashes_table[index], ht_values_table[index]->value);
                        if(value_ptr == nullptr){
                            return false;
                        }
                    }
                }
                return true;
            }
        }

        template<typename V2, typename Hash2, typename Equal2, typename Alloc2>
        friend bool operator==(const hash_table_list_set<V2, Hash2, Equal2, Alloc2>& lhs, const hash_table_list_set<V2, Hash2, Equal2, Alloc2>& rhs);

        template<typename V2, typename Hash2, typename Equal2, typename Alloc2>
        friend bool operator!=(const hash_table_list_set<V2, Hash2, Equal2, Alloc2>& lhs, const hash_table_list_set<V2, Hash2, Equal2, Alloc2>& rhs);

        template<typename F=no_filter<V>>
        hash_table_list_set copy(F filter=F(), CopyPolicy copy_policy = CopyPolicy::keep_source_capacity) const{
            hash_table_list_set result(0, static_cast<const Allocator&>(*this));
            this->copy_into_and_replace(result, std::forward<F>(filter), copy_policy);
            return result;
        }

    protected:

        size_t insert_many_impl(){return 0;};
        template<typename H, typename ...Elms> size_t insert_many_impl(H &&h, Elms&&... elms){
            return (insert_value(std::forward<H>(h)) >= 0) + insert_many_impl(std::forward<Elms>(elms)...);
        };

        size_t emplace_many_impl(){return 0;};
        template<typename H, typename ...Elms> size_t emplace_many_impl(H &&h, Elms&&... elms){
            return (emplace_value(std::forward<H>(h)) >= 0) + emplace_many_impl(std::forward<Elms>(elms)...);
        };

        hash_type calculate_hash (const V& value) const noexcept{
            return (hash_type) (Hash()(value));
        }

        bool equality_check(const V& lhs, const V& rhs) const noexcept{
            return Equal()(lhs, rhs);
        }

        /* ---------------------------- search and insert operations ------------------------------ */

        index_type find_existing_index (const V& value, hash_type hash, hash_type modded_hash) const noexcept{
            ListNode<V>** ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*);
            HT_FIND_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                if(equality_check(ht_value_table[index]->value, value)){
                    return index;
                }
            HT_FIND_INDEX_END(this->m_table_size, -1)
        }

        V* find_existing_ptr (const V& value, hash_type hash, hash_type modded_hash) const noexcept{
            ListNode<V>** ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*);
            HT_FIND_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                V* ptr = &(ht_value_table[index]->value);
                if(equality_check(*ptr, value)){
                    return ptr;
                }
            HT_FIND_INDEX_END(this->m_table_size, nullptr)
        }

        index_type find_free_index (const V& value, hash_type hash, hash_type modded_hash) const noexcept{
            ListNode<V>** ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*);
            HT_FIND_FREE_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                if(equality_check(ht_value_table[index]->value, value)){
                    return -1;
                }
            HT_FIND_FREE_INDEX_END(this->m_table_size)
        }

        index_type find_existing_or_free_index (const V& value, hash_type hash, hash_type modded_hash) const noexcept{
            ListNode<V>** ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*);
            HT_FIND_FREE_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                if(equality_check(ht_value_table[index]->value, value)){
                    return index;
                }
            HT_FIND_FREE_INDEX_END(this->m_table_size)
        }
    };


    /* --------------------------------------------------------------------------------------
                                        MAP - LIST TABLE
       -------------------------------------------------------------------------------------- */

    template<typename KvpAdapter, class Hash>
    struct PairHasher{
        using pair_type = typename KvpAdapter::pair_type;
        using key_type = typename KvpAdapter::key_type;
        hash_type operator()(const pair_type& value) const noexcept{
            return Hash()(KvpAdapter().key(value));
        }
        hash_type operator()(const key_type& key) const noexcept{
            return Hash()(key);
        }
    };

    template<
        class K,
        class V,
        class KvpAdapter = StdPairKvpAdapter<K, V>,
        class Hash = std::hash<K>,
        class EqualKey = std::equal_to<K>,
        class EqualValue = std::equal_to<V>,
        class Allocator = std::allocator<char>
    >
    class hash_table_list_map : public hash_table_list_container<typename KvpAdapter::pair_type, PairHasher<KvpAdapter, Hash>, Allocator>{
        using BaseClass = hash_table_list_container<typename KvpAdapter::pair_type, PairHasher<KvpAdapter, Hash>, Allocator>;
    public:
        using allocator = Allocator;
        using element_type = typename BaseClass::element_type;
        using key_type = K;
        using value_type = V;
        using pair_type = typename KvpAdapter::pair_type;
        using hash_function = Hash;
        using key_equality_function = EqualKey;
        using value_equality_function = EqualValue;
        using kvp_adapter = KvpAdapter;
        using iterator = typename BaseClass::iterator;
        using const_iterator = typename BaseClass::const_iterator;
        using reverse_iterator = typename BaseClass::reverse_iterator;
        using const_reverse_iterator = typename BaseClass::const_reverse_iterator;

        /* ------------------------- boilerplate ---------------------------- */

        explicit hash_table_list_map(size_t capacity=0, Allocator&& alloc=Allocator()) : BaseClass(capacity, std::move(alloc)) {}
        explicit hash_table_list_map(size_t capacity, const Allocator& alloc) : BaseClass(capacity, alloc) {}
        hash_table_list_map(const hash_table_list_map& src) : BaseClass(src) {}
        hash_table_list_map(hash_table_list_map&& src) noexcept : BaseClass(std::move(src)) {}
        hash_table_list_map& operator=(const hash_table_list_map& src){return static_cast<hash_table_list_map&>(BaseClass::operator=(src));}
        hash_table_list_map& operator=(hash_table_list_map&& src){return static_cast<hash_table_list_map&> (BaseClass::operator=(std::move(src)));}

        /* -------------------------- container operations interface ------------------------------- */

        pair_type& get_value(index_type index)const noexcept{
            return HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index]->value;
        }

        index_type find_index(const K& key) const noexcept{
            hash_type hash = calculate_hash(key);
            return find_index_h(hash, key);
        }

        pair_type* find_ptr(const K& key) const noexcept{
            hash_type hash = calculate_hash(key);
            return find_ptr_h(hash, key);
        }

        // if using normal constructors for elements
        template<typename ...Elms> size_t insert_many(Elms&&... elms){
            this->expand_capacity(this->m_elements+sizeof...(Elms));
            return insert_many_impl(std::forward<Elms>(elms)...);
        };

        // if using normal constructors for elements
        template<typename ...Elms> size_t emplace_many(Elms&&... elms){
            this->expand_capacity(this->m_elements+sizeof...(Elms));
            return emplace_many_impl(std::forward<Elms>(elms)...);
        };

        // if using brace-initialization for elements
        size_t insert_many_il(std::initializer_list<pair_type> elms){
            this->expand_capacity(this->m_elements+elms.size());
            size_t inserted = 0;
            for(auto& v : elms){
                if(insert_value(v) >= 0)
                    inserted++;
            }
            return inserted;
        };

        // if using iterators for elements
        template<class InputIterator> size_t insert_many_it(InputIterator it_start, InputIterator it_end){
            size_t n_inserts = 0;
            for (; it_start != it_end; ++it_start){
                n_inserts += (insert_value(*it_start) >= 0 ? 1 : 0);
            }
            return n_inserts;
        }

        index_type insert_value(const pair_type& kvp){
            hash_type hash = calculate_hash(KvpAdapter().key(kvp));
            return insert_value_h(hash, kvp);
        }

        index_type insert_value(pair_type&& kvp){
            hash_type hash = calculate_hash(KvpAdapter().key(kvp));
            return insert_value_h(hash, std::move(kvp));
        }

        index_type insert_value(const K& key, const V& value){
            hash_type hash = calculate_hash(key);
            return insert_value_h(hash, key, value);
        }

        index_type insert_value(K&& key, const V& value){
            hash_type hash = calculate_hash(key);
            return insert_value_h(hash, std::move(key), value);
        }

        index_type insert_value(const K& key, V&& value){
            hash_type hash = calculate_hash(key);
            return insert_value_h(hash, key, std::move(value));
        }

        index_type insert_value(K&& key, V&& value){
            hash_type hash = calculate_hash(key);
            return insert_value_h(hash, std::move(key), std::move(value));
        }

        insert_result insert_or_find_value(const pair_type& kvp){
            hash_type hash = calculate_hash(KvpAdapter().key(kvp));
            return insert_or_replace_value_h(hash, kvp);
        }

        insert_result insert_or_find_value(pair_type&& kvp){
            hash_type hash = calculate_hash(KvpAdapter().key(kvp));
            return insert_or_replace_value_h(hash, std::move(kvp));
        }

        insert_result insert_or_find_value(const K& key, const V& value){
            hash_type hash = calculate_hash(key);
            return insert_or_replace_value_h(hash, key, value);
        }

        insert_result insert_or_find_value(K&& key, const V& value){
            hash_type hash = calculate_hash(key);
            return insert_or_replace_value_h(hash, std::move(key), value);
        }

        insert_result insert_or_find_value(const K& key, V&& value){
            hash_type hash = calculate_hash(key);
            return insert_or_replace_value_h(hash, key, std::move(value));
        }

        insert_result insert_or_find_value(K&& key, V&& value){
            hash_type hash = calculate_hash(key);
            return insert_or_replace_value_h(hash, std::move(key), std::move(value));
        }

        insert_result insert_or_replace_value(const pair_type& kvp){
            hash_type hash = calculate_hash(KvpAdapter().key(kvp));
            return insert_or_replace_value_h(hash, kvp);
        }

        insert_result insert_or_replace_value(pair_type&& kvp){
            hash_type hash = calculate_hash(KvpAdapter().key(kvp));
            return insert_or_replace_value_h(hash, std::move(kvp));
        }

        insert_result insert_or_replace_value(const K& key, const V& value){
            hash_type hash = calculate_hash(key);
            return insert_or_replace_value_h(hash, key, value);
        }

        insert_result insert_or_replace_value(K&& key, const V& value){
            hash_type hash = calculate_hash(key);
            return insert_or_replace_value_h(hash, std::move(key), value);
        }

        insert_result insert_or_replace_value(const K& key, V&& value){
            hash_type hash = calculate_hash(key);
            return insert_or_replace_value_h(hash, key, std::move(value));
        }

        insert_result insert_or_replace_value(K&& key, V&& value){
            hash_type hash = calculate_hash(key);
            return insert_or_replace_value_h(hash, std::move(key), std::move(value));
        }

        template<typename... ARGS> index_type emplace_value(const K& key, ARGS&&... args){
            hash_type hash = calculate_hash(key);
            return emplace_value_h(hash, key, std::forward<ARGS>(args)...);
        }

        template<typename... ARGS> index_type emplace_value(K&& key, ARGS&&... args){
            hash_type hash = calculate_hash(key);
            return emplace_value_h(hash, std::move(key), std::forward<ARGS>(args)...);
        }

        template<typename... ARGS> insert_result emplace_or_find_value(const K& key, ARGS&&... args){
            hash_type hash = calculate_hash(key);
            return emplace_or_find_value_h(hash, key, std::forward<ARGS>(args)...);
        }

        template<typename... ARGS> insert_result emplace_or_find_value(K&& key, ARGS&&... args){
            hash_type hash = calculate_hash(key);
            return emplace_or_find_value_h(hash, std::move(key), std::forward<ARGS>(args)...);
        }

        template<typename... ARGS> insert_result emplace_or_replace_value(const K& key, ARGS&&... args){
            hash_type hash = calculate_hash(key);
            return emplace_or_replace_value_h(hash, key, std::forward<ARGS>(args)...);
        }

        template<typename... ARGS> insert_result emplace_or_replace_value(K&& key, ARGS&&... args){
            hash_type hash = calculate_hash(key);
            return emplace_or_replace_value_h(hash, std::move(key), std::forward<ARGS>(args)...);
        }

        index_type erase_value(const K& key){
            hash_type hash = calculate_hash(key);
            return erase_value_h(hash, key);
        }

        iterator erase_value_and_get_next(const V& value){
            hash_type hash = calculate_hash(value);
            return erase_value_and_get_next_h(hash, value);
        }

        index_type find_index_h(hash_type hash, const K& key) const noexcept{
            hash_type modded_hash = this->calculate_modded_hash(hash);
            return find_existing_index(key, hash, modded_hash);
        }

        index_type find_index_h(hash_type hash, const pair_type& kvp) const noexcept{
            hash_type modded_hash = this->calculate_modded_hash(hash);
            return find_existing_index(KvpAdapter().key(kvp), hash, modded_hash);
        }

        pair_type* find_ptr_h(hash_type hash, const K& key) const noexcept{
            hash_type modded_hash = this->calculate_modded_hash(hash);
            return find_existing_ptr(key, hash, modded_hash);
        }

        index_type insert_value_h(hash_type hash, const pair_type& kvp){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(KvpAdapter().key(kvp), hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(kvp);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        index_type insert_value_h(hash_type hash, pair_type&& kvp){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(KvpAdapter().key(kvp), hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(std::move(kvp));
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        index_type insert_value_h(hash_type hash, const K& key, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(key, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(key, value);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        index_type insert_value_h(hash_type hash, K&& key, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(key, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(std::move(key), value);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        index_type insert_value_h(hash_type hash, const K& key, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(key, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(key, std::move(value));
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        index_type insert_value_h(hash_type hash, K&& key, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(key, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(std::move(key), std::move(value));
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        insert_result insert_or_find_value_h(hash_type hash, const pair_type& kvp){
            this->expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(KvpAdapter().key(kvp), hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(kvp);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_find_value_h(hash_type hash, pair_type&& kvp){
            this->expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(KvpAdapter().key(kvp), hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(std::move(kvp));
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_find_value_h(hash_type hash, const K& key, const V& value){
            this->expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(key, value);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_find_value_h(hash_type hash, K&& key, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(std::move(key), value);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_find_value_h(hash_type hash, const K& key, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(key, std::move(value));
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_find_value_h(hash_type hash, K&& key, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(std::move(key), std::move(value));
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, const pair_type& kvp){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(KvpAdapter().key(kvp), hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index]->value) = KvpAdapter().value(kvp);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(kvp);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, pair_type&& kvp){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(KvpAdapter().key(kvp), hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index]->value) = std::move(KvpAdapter().value(kvp));
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(std::move(kvp));
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, const K& key, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index]->value) = value;
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(key, value);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, K&& key, const V& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index]->value) = value;
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(std::move(key), value);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, const K& key, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index]->value) = std::move(value);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(key, std::move(value));
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        insert_result insert_or_replace_value_h(hash_type hash, K&& key, V&& value){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index]->value) = std::move(value);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = this->insert_node(std::move(key), std::move(value));
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        template<typename... ARGS>
        index_type emplace_value_h(hash_type hash, const K& key, ARGS&&... args){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(key, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = static_cast<ListNode<pair_type>*>(this->mem_alloc(sizeof(ListNode<pair_type>)));
                ::new (static_cast<void*>(&(KvpAdapter().key(node->value)))) K(key);
                ::new (static_cast<void*>(&(KvpAdapter().value(node->value)))) V(std::forward<ARGS>(args)...);
                this->insert_node_at_end(node);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        template<typename... ARGS>
        index_type emplace_value_h(hash_type hash, K&& key, ARGS&&... args){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_free_index(key, hash, modded_hash);
            if(index >= 0){
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = static_cast<ListNode<pair_type>*>(this->mem_alloc(sizeof(ListNode<pair_type>)));
                ::new (static_cast<void*>(&(KvpAdapter().key(node->value)))) K(std::move(key));
                ::new (static_cast<void*>(&(KvpAdapter().value(node->value)))) V(std::forward<ARGS>(args)...);
                this->insert_node_at_end(node);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
            }
            return index;
        }

        template<typename... ARGS>
        insert_result emplace_or_find_value_h(hash_type hash, const K& key, ARGS&&... args){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index]->value) = V(std::forward<ARGS>(args)...);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = static_cast<ListNode<pair_type>*>(this->mem_alloc(sizeof(ListNode<pair_type>)));
                ::new (static_cast<void*>(&(KvpAdapter().key(node->value)))) K(key);
                ::new (static_cast<void*>(&(KvpAdapter().value(node->value)))) V(std::forward<ARGS>(args)...);
                this->insert_node_at_end(node);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        template<typename... ARGS>
        insert_result emplace_or_find_value_h(hash_type hash, K&& key, ARGS&&... args){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index]->value) = V(std::forward<ARGS>(args)...);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = static_cast<ListNode<pair_type>*>(this->mem_alloc(sizeof(ListNode<pair_type>)));
                ::new (static_cast<void*>(&(KvpAdapter().key(node->value)))) K(std::move(key));
                ::new (static_cast<void*>(&(KvpAdapter().value(node->value)))) V(std::forward<ARGS>(args)...);
                this->insert_node_at_end(node);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        template<typename... ARGS>
        insert_result emplace_or_replace_value_h(hash_type hash, const K& key, ARGS&&... args){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index]->value) = V(std::forward<ARGS>(args)...);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = static_cast<ListNode<pair_type>*>(this->mem_alloc(sizeof(ListNode<pair_type>)));
                ::new (static_cast<void*>(&(KvpAdapter().key(node->value)))) K(key);
                ::new (static_cast<void*>(&(KvpAdapter().value(node->value)))) V(std::forward<ARGS>(args)...);
                this->insert_node_at_end(node);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        template<typename... ARGS>
        insert_result emplace_or_replace_value_h(hash_type hash, K&& key, ARGS&&... args){
            this->check_and_expand_full_capacity();
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_or_free_index(key, hash, modded_hash);
            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                KvpAdapter().value(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index]->value) = V(std::forward<ARGS>(args)...);
                return {index, false};
            } else {
                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type> *node = static_cast<ListNode<pair_type>*>(this->mem_alloc(sizeof(ListNode<pair_type>)));
                ::new (static_cast<void*>(&(KvpAdapter().key(node->value)))) K(std::move(key));
                ::new (static_cast<void*>(&(KvpAdapter().value(node->value)))) V(std::forward<ARGS>(args)...);
                this->insert_node_at_end(node);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                this->m_elements++;
                this->m_elements_to_expand--;
                return {index, true};
            }
        }

        index_type erase_value_h(hash_type hash, const K& key){
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_index(key, hash, modded_hash);
            if(index >= 0){
                HT_DELETE_ENTRY(index, this->m_hash_table, this->m_table_size)
                this->remove_node(HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index]);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<V>*)[index] = nullptr;
                this->m_elements--;
                this->m_elements_to_expand++;
            }
            return index;
        }

        iterator erase_value_and_get_next_h(hash_type hash, const K& key){
            hash_type modded_hash = this->calculate_modded_hash(hash);
            index_type index = find_existing_index(key, hash, modded_hash);
            if(index >= 0){
                HT_DELETE_ENTRY(index, this->m_hash_table, this->m_table_size)
                ListNode<pair_type>* node = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index];
                ListNode<pair_type>* next_node = node->next;
                this->remove_node(node);
                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = nullptr;
                this->m_elements--;
                this->m_elements_to_expand++;
                return iterator(next_node);
            } else {
                return this->end();
            }
        }

        size_t merge_from(const hash_table_list_map& source, OverlappingPolicy merge_policy=OverlappingPolicy::ignore_duplicates){
            this->expand_capacity(this->m_elements + source.m_elements);
            size_t result = 0;
            switch(merge_policy){
                case OverlappingPolicy::ignore_duplicates:{
                    ListNode<pair_type>* source_list_head = source.m_list_head;
                    while(source_list_head != nullptr){
                        hash_type hash = this->calculate_hash(KvpAdapter().key(source_list_head->value));
                        hash_type modded_hash = this->calculate_modded_hash(hash);
                        index_type index = find_free_index(KvpAdapter().key(source_list_head->value), hash, modded_hash);
                        if(index >= 0){
                            HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                            ListNode<pair_type>* node = this->copy_node(source_list_head);
                            HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                            this->m_elements++;
                            this->m_elements_to_expand--;
                            result++;
                        }
                        source_list_head = source_list_head->next;
                    }
                } break;
                case OverlappingPolicy::replace_duplicates:{
                    ListNode<pair_type>* source_list_head = source.m_list_head;
                    while(source_list_head != nullptr){
                        hash_type hash = this->calculate_hash(KvpAdapter().key(source_list_head->value));
                        hash_type modded_hash = this->calculate_modded_hash(hash);
                        index_type index = find_existing_or_free_index(KvpAdapter().key(source_list_head->value), hash, modded_hash);
                        if(index >= 0){
                            if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index]->value = source_list_head->value;
                            } else {
                                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                                ListNode<pair_type>* node = this->copy_node(source_list_head);
                                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                                this->m_elements++;
                                this->m_elements_to_expand--;
                            }
                            result++;
                        }
                        source_list_head = source_list_head->next;
                    }
                } break;
                default:
                    break;
            }
            return result;
        }

        size_t merge_from(hash_table_list_map&& source, OverlappingPolicy merge_policy=OverlappingPolicy::ignore_duplicates){
            this->expand_capacity(this->m_elements + source.m_elements);
            size_t result = 0;
            switch(merge_policy){
                case OverlappingPolicy::ignore_duplicates:{
                    ListNode<pair_type>* source_list_head = source.m_list_head;
                    if(static_cast<Allocator&>(*this) == static_cast<Allocator&>(source)){
                        while(source_list_head != nullptr){
                            ListNode<pair_type>* next_node = source_list_head->next;
                            hash_type hash = this->calculate_hash(KvpAdapter().key(source_list_head->value));
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type index = find_free_index(KvpAdapter().key(source_list_head->value), hash, modded_hash);
                            if(index >= 0){
                                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                                ListNode<pair_type>* node = source_list_head;
                                source.detatch_node(node);
                                this->insert_node_at_end(node);
                                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                                this->m_elements++;
                                this->m_elements_to_expand--;
                                result++;
                            }
                            source_list_head = next_node;
                        }
                    } else {
                        while(source_list_head != nullptr){
                            ListNode<pair_type>* next_node = source_list_head->next;
                            hash_type hash = this->calculate_hash(KvpAdapter().key(source_list_head->value));
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type index = find_free_index(KvpAdapter().key(source_list_head->value), hash, modded_hash);
                            if(index >= 0){
                                HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                                ListNode<pair_type>* node = this->insert_node(std::move(source_list_head->value));
                                HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                                this->m_elements++;
                                this->m_elements_to_expand--;
                                result++;
                            }
                            source_list_head = next_node;
                        }
                    }

                } break;
                case OverlappingPolicy::replace_duplicates:{
                    ListNode<pair_type>* source_list_head = source.m_list_head;
                    if(static_cast<Allocator&>(*this) == static_cast<Allocator&>(source)){
                        while(source_list_head != nullptr){
                            ListNode<pair_type>* next_node = source_list_head->next;
                            hash_type hash = this->calculate_hash(KvpAdapter().key(source_list_head->value));
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type index = find_existing_or_free_index(KvpAdapter().key(source_list_head->value), hash, modded_hash);
                            if(index >= 0){
                                if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                                    ListNode<pair_type>* target_node = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index];
                                    source.detatch_node(source_list_head);
                                    this->replace_node(source_list_head, target_node);
                                    target_node->value.~pair_type();
                                    this->mem_free(target_node, sizeof(ListNode<pair_type>));
                                    HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = source_list_head;
                                } else {
                                    HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                                    source.detatch_node(source_list_head);
                                    this->insert_node_at_end(source_list_head);
                                    HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = source_list_head;
                                    this->m_elements++;
                                    this->m_elements_to_expand--;
                                }
                                result++;
                            }
                            source_list_head = next_node;
                        }
                    } else {
                        while(source_list_head != nullptr){
                            ListNode<pair_type>* next_node = source_list_head->next;
                            hash_type hash = this->calculate_hash(KvpAdapter().key(source_list_head->value));
                            hash_type modded_hash = this->calculate_modded_hash(hash);
                            index_type index = find_existing_or_free_index(KvpAdapter().key(source_list_head->value), hash, modded_hash);
                            if(index >= 0){
                                if(HT_VALUE_VALID(HT_GET_METADATA_TABLE(this->m_hash_table)[index])){
                                    ListNode<pair_type>* target_node = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index];
                                    target_node->value = std::move(source_list_head->value);
                                    HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = source_list_head;
                                } else {
                                    HT_INSERT_ENTRY(hash, modded_hash, index, this->m_hash_table, this->m_table_size)
                                    ListNode<pair_type>* node = this->insert_node(std::move(source_list_head->value));
                                    HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*)[index] = node;
                                    this->m_elements++;
                                    this->m_elements_to_expand--;
                                }
                                result++;
                            }
                            source_list_head = next_node;
                        }
                    }
                } break;
                default:
                    break;
            }
            source.clear();
            return result;
        }

        bool equals(const hash_table_list_map& other) const noexcept{
            if(this->m_elements != other.m_elements)
                return false;
            if(this->m_table_size < other.m_table_size){
                HT_GET_TABLES(this->m_hash_table, this->m_table_size, ListNode<pair_type>*, sizeof(ListNode<pair_type>*))
                for(size_t index=0; index < this->m_table_size; index++){
                    if(HT_VALUE_VALID(ht_metadata_table[index])){
                        pair_type* kvp_ptr = other.find_ptr_h(ht_hashes_table[index], KvpAdapter().key(ht_values_table[index]->value));
                        if(kvp_ptr == nullptr || !value_equality_check(*kvp_ptr, KvpAdapter().value(ht_values_table[index]->value))){
                            return false;
                        }
                    }
                }
                return true;
            } else {
                HT_GET_TABLES(other.m_hash_table, other.m_table_size, ListNode<pair_type>*, sizeof(ListNode<pair_type>*))
                for(size_t index=0; index < other.m_table_size; index++){
                    if(HT_VALUE_VALID(ht_metadata_table[index])){
                        pair_type* kvp_ptr = this->find_ptr_h(ht_hashes_table[index], KvpAdapter().key(ht_values_table[index]->value));
                        if(kvp_ptr == nullptr || !value_equality_check(*kvp_ptr, KvpAdapter().value(ht_values_table[index]->value))){
                            return false;
                        }
                    }
                }
                return true;
            }
        }

        template<typename K2, typename V2, typename KvpAdapter2, typename Hash2, typename EqualKey2, typename EqualValue2, typename Alloc2>
        friend bool operator==(const hash_table_list_map<K2, V2, KvpAdapter2, Hash2, EqualKey2, EqualValue2, Alloc2>& lhs, const hash_table_list_map<K2, V2, KvpAdapter2, Hash2, EqualKey2, EqualValue2, Alloc2>& rhs);

        template<typename K2, typename V2, typename KvpAdapter2, typename Hash2, typename EqualKey2, typename EqualValue2, typename Alloc2>
        friend bool operator!=(const hash_table_list_map<K2, V2, KvpAdapter2, Hash2, EqualKey2, EqualValue2, Alloc2>& lhs, const hash_table_list_map<K2, V2, KvpAdapter2, Hash2, EqualKey2, EqualValue2, Alloc2>& rhs);

        template<typename F=no_filter<pair_type>>
        hash_table_list_map copy(F filter=F(), CopyPolicy copy_policy = CopyPolicy::keep_source_capacity) const{
            hash_table_list_map result(0, static_cast<const Allocator&>(*this));
            this->copy_into_and_replace(result, std::forward<F>(filter), copy_policy);
            return result;
        }


    protected:

        size_t insert_many_impl(){return 0;};
        template<typename H, typename ...Elms> size_t insert_many_impl(H &&h, Elms&&... elms){
            return (insert_value(std::forward<H>(h)) >= 0) + insert_many_impl(std::forward<Elms>(elms)...);
        };

        size_t emplace_many_impl(){return 0;};
        template<typename H, typename ...Elms> size_t emplace_many_impl(H &&h, Elms&&... elms){
            return (emplace_value(std::forward<H>(h)) >= 0) + emplace_many_impl(std::forward<Elms>(elms)...);
        };

        hash_type calculate_hash (const K& key) const noexcept{
            return (hash_type) (Hash()(key));
        }

        bool key_equality_check(const pair_type& lhs, const K& rhs) const noexcept{
            return EqualKey()(KvpAdapter().key(lhs), rhs);
        }

        bool value_equality_check(const pair_type& lhs, const K& rhs) const noexcept{
            return EqualValue()(KvpAdapter().value(lhs), rhs);
        }

        index_type find_existing_index (const K& key, hash_type hash, hash_type modded_hash) const noexcept{
            ListNode<pair_type>** ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*);
            HT_FIND_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                if(key_equality_check(ht_value_table[index]->value, key)){
                    return index;
                }
            HT_FIND_INDEX_END(this->m_table_size, -1)
        }

        pair_type* find_existing_ptr (const K& key, hash_type hash, hash_type modded_hash) const noexcept{
            ListNode<pair_type>** ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*);
            HT_FIND_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                pair_type* ptr = &(ht_value_table[index]->value);
                if(key_equality_check(*ptr, key)){
                    return ptr;
                }
            HT_FIND_INDEX_END(this->m_table_size, nullptr)
        }

        index_type find_free_index (const K& key, hash_type hash, hash_type modded_hash) const noexcept{
            ListNode<pair_type>** ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*);
            HT_FIND_FREE_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                if(key_equality_check(ht_value_table[index]->value, key)){
                    return -1;
                }
            HT_FIND_FREE_INDEX_END(this->m_table_size)
        }

        index_type find_existing_or_free_index (const K& key, hash_type hash, hash_type modded_hash) const noexcept{
            ListNode<pair_type>** ht_value_table = HT_GET_VALUES_TABLE(this->m_hash_table, this->m_table_size, ListNode<pair_type>*);
            HT_FIND_FREE_INDEX_BEGIN(hash, modded_hash, this->m_hash_table, this->m_table_size)
                if(key_equality_check(ht_value_table[index]->value, key)){
                    return index;
                }
            HT_FIND_FREE_INDEX_END(this->m_table_size)
        }
    };


    /* --------------------------------------------------------------------------------------
                                        COPY FILTERS
       -------------------------------------------------------------------------------------- */

    // ------------------------- FILTER IMPLEMENTATIONS --------------------
    namespace filter_impl{
        template<typename HT, typename LHS, typename RHS> struct filters_and_impl;
        template<typename HT, typename LHS, typename RHS> struct filters_or_impl;
        template<typename HT, typename ARG> struct filter_not_impl;

        template<typename HT>
        struct filter_base{
            using table_type = HT;
            template<typename LHS, typename RHS> friend filters_and_impl<typename LHS::table_type, LHS, RHS> operator&&(const LHS&, const RHS&);
            template<typename LHS, typename RHS> friend filters_or_impl<typename LHS::table_type, LHS, RHS> operator||(const LHS&, const RHS&);
            template<typename ARG> friend filter_not_impl<typename ARG::table_type, ARG> operator!(const ARG&);
        };

        template<typename HT, typename LHS, typename RHS>
        struct filters_and_impl{
            using table_type = HT;
            filters_and_impl(const LHS& lhs, const RHS& rhs) : lhs(&lhs), rhs(&rhs){}
            bool operator()(hash_type hash, const typename HT::element_type& e) const noexcept{
                return (*lhs)(hash, e) && (*rhs)(hash, e);
            }
            const LHS *lhs;
            const RHS *rhs;
        };

        template<typename LHS, typename RHS, typename std::enable_if<std::is_base_of<filter_base<typename LHS::table_type>, LHS>::value && std::is_base_of<filter_base<typename RHS::filter_type>, RHS>::value>::type* = nullptr>
        inline filters_and_impl<typename LHS::table_type, LHS, RHS> operator&&(const LHS& lhs, const RHS& rhs){
            return filters_and_impl<typename LHS::table_type, LHS, RHS>(lhs, rhs);
        }

        template<typename HT, typename LHS, typename RHS>
        struct filters_or_impl{
            using table_type = HT;
            filters_or_impl(const LHS& lhs, const RHS& rhs) : lhs(&lhs), rhs(&rhs){}
            bool operator()(hash_type hash, const typename HT::element_type& e) const noexcept{
                return (*lhs)(hash, e) || (*rhs)(hash, e);
            }
            const LHS *lhs;
            const RHS *rhs;
        };

        template<typename LHS, typename RHS, typename std::enable_if<std::is_base_of<filter_base<typename LHS::table_type>, LHS>::value && std::is_base_of<filter_base<typename RHS::filter_type>, RHS>::value>::type* = nullptr>
        inline filters_or_impl<typename LHS::table_type, LHS, RHS> operator||(const LHS& lhs, const RHS& rhs){
            return filters_or_impl<typename LHS::table_type, LHS, RHS>(lhs, rhs);
        }

        template<typename HT, typename ARG>
        struct filter_not_impl{
            using table_type = HT;
            filter_not_impl(const ARG& arg) : arg(&arg){}
            bool operator()(hash_type hash, const typename HT::element_type& e) const noexcept{
                return !(*arg)(hash, e);
            }
            const ARG *arg;
        };

        template<typename ARG, typename std::enable_if<std::is_base_of<filter_base<typename ARG::table_type>, ARG>::value>::type* = nullptr>
        inline filter_not_impl<typename ARG::table_type, ARG> operator!(const ARG& arg){
            return filter_not_impl<typename ARG::table_type, ARG>(arg);
        }


        template<typename HT>
        struct subtract_impl : public filter_base<HT>{
            using table_type = HT;
            subtract_impl(const HT& ht) : ht(&ht){}
            bool operator()(hash_type hash, const typename HT::element_type& e) const noexcept{
                return ht->find_index_h(hash, e) < 0;
            }
            const HT* ht;
        };

        template<typename HT, typename Arg1, typename Arg2, typename ...Args>
        struct filters_and_many_impl : public filter_base<HT>{
            using table_type = HT;
            filters_and_many_impl(const Arg1& arg1, const Arg1& arg2, const Args&... args){
                set_argument(arg1, arg2, args...);
            }
            void set_argument(){};
            template<typename H, typename ...Elms> void set_argument(const H &h, Elms&&... elms){
                operands[(2 + sizeof...(Args)) - sizeof...(Elms) - 1] = &h;
                set_argument(std::forward<Elms>(elms)...);
            };

            bool operator()(hash_type hash, const typename HT::element_type& e) const noexcept{
                return call_impl<Arg1, Arg2, Args...>(hash, e);
            }

            template<typename H, typename ...Hs, typename std::enable_if<sizeof...(Hs) >= 1, void*>::type = nullptr>
            bool call_impl(hash_type hash, const typename HT::element_type& e)const noexcept{
                if(!((*(static_cast<const H*>(operands[(2 + sizeof...(Args)) - sizeof...(Hs) - 1])))(hash, e)))
                    return false;
                if(sizeof...(Hs) > 0){
                    return call_impl<Hs...>(hash, e);
                } else {
                    return true;
                }
            }

            template<typename H>
            bool call_impl(hash_type hash, const typename HT::element_type& e)const noexcept{
                if(!((*(static_cast<const H*>(operands[(2 + sizeof...(Args)) - 1])))(hash, e)))
                    return false;
                return true;
            }

            const filter_base<HT>* operands[2 + sizeof...(Args)];
        };

        template<typename HT, typename Arg1, typename Arg2, typename ...Args>
        struct filters_or_many_impl : public filter_base<HT>{
            using table_type = HT;
            filters_or_many_impl(const Arg1& arg1, const Arg1& arg2, const Args&... args){
                set_argument(arg1, arg2, args...);
            }
            void set_argument(){};
            template<typename H, typename ...Elms> void set_argument(const H &h, Elms&&... elms){
                operands[(2 + sizeof...(Args)) - sizeof...(Elms) - 1] = &h;
                set_argument(std::forward<Elms>(elms)...);
            };

            bool operator()(hash_type hash, const typename HT::element_type& e) const noexcept{
                return call_impl<Arg1, Arg2, Args...>(hash, e);
            }

            template<typename H, typename ...Hs, typename std::enable_if<sizeof...(Hs) >= 1, void*>::type = nullptr>
            bool call_impl(hash_type hash, const typename HT::element_type& e)const noexcept{
                if(((*(static_cast<const H*>(operands[(2 + sizeof...(Args)) - sizeof...(Hs) - 1])))(hash, e)))
                    return true;
                if(sizeof...(Hs) > 0){
                    return call_impl<Hs...>(hash, e);
                } else {
                    return false;
                }
            }

            template<typename H>
            bool call_impl(hash_type hash, const typename HT::element_type& e)const noexcept{
                if(((*(static_cast<const H*>(operands[(2 + sizeof...(Args)) - 1])))(hash, e)))
                    return true;
                return false;
            }

            const filter_base<HT>* operands[2 + sizeof...(Args)];
        };

        template<typename HT, typename ...Args>
        struct subtract_many_impl : public filter_base<HT>{
            using table_type = HT;
            subtract_many_impl(const Args&... args){
                set_argument(args...);
            }
            void set_argument(){};
            template<typename H, typename ...Elms> void set_argument(const H &h, Elms&&... elms){
                operands[sizeof...(Args) - sizeof...(Elms) - 1] = &h;
                set_argument(std::forward<Elms>(elms)...);
            };

            bool operator()(hash_type hash, const typename HT::element_type& e) const noexcept{
                for(size_t i=0; i<sizeof...(Args); i++){
                    if(operands[i]->find_index_h(hash, e) >= 0)
                        return false;
                }
                return true;
            }

            const HT* operands[sizeof...(Args)];
        };

        template<typename HT>
        struct intersect_impl : public filter_base<HT>{
            using table_type = HT;
            intersect_impl(const HT& ht) : ht(&ht){}
            const HT* ht;
            bool operator()(hash_type hash, const typename HT::element_type& e) const noexcept{
                return ht->find_index_h(hash, e) >= 0;
            }
        };

        template<typename HT, typename ...Args>
        struct intersect_many_impl : public filter_base<HT>{
            using table_type = HT;
            intersect_many_impl(const Args&... args){
                set_argument(args...);
            }
            void set_argument(){};
            template<typename H, typename ...Elms> void set_argument(const H& h, Elms&&... elms){
                operands[sizeof...(Args) - sizeof...(Elms) - 1] = &h;
                set_argument(std::forward<Elms>(elms)...);
            };

            bool operator()(hash_type hash, const typename HT::element_type& e) const noexcept{
                for(size_t i=0; i<sizeof...(Args); i++){
                    if(operands[i]->find_index_h(hash, e) < 0)
                        return false;
                }
                return true;
            }

            const HT* operands[sizeof...(Args)];
        };
    }

    // -------------------------------- FILTER CONSTRUCTORS ------------------------------
    namespace filters{
        template<typename LHS, typename RHS>
        filter_impl::filters_and_impl<typename LHS::table_type, LHS, RHS> filters_and(const LHS& lhs, const RHS& rhs){
            return filter_impl::filters_and_impl<typename LHS::table_type, LHS, RHS>(lhs, rhs);
        }
        template<typename Arg1, typename Arg2, typename ...Args>
        filter_impl::filters_and_many_impl<typename Arg1::table_type, Arg1, Arg2, Args...> filters_and(const Arg1& arg1, const Arg2& arg2, Args&&... args){
            return filter_impl::filters_and_many_impl<typename Arg1::table_type, Arg1, Arg2, Args...>(arg1, arg2, std::forward<Args>(args)...);
        }


        template<typename LHS, typename RHS>
        filter_impl::filters_or_impl<typename LHS::table_type, LHS, RHS> filters_or(const LHS& lhs, const RHS& rhs){
            return filter_impl::filters_or_impl<typename LHS::table_type, LHS, RHS>(lhs, rhs);
        }
        template<typename Arg1, typename Arg2, typename ...Args>
        filter_impl::filters_or_many_impl<typename Arg1::table_type, Arg1, Arg2, Args...> filters_or(const Arg1& arg1, const Arg2& arg2, Args&&... args){
            return filter_impl::filters_or_many_impl<typename Arg1::table_type, Arg1, Arg2, Args...>(arg1, arg2, std::forward<Args>(args)...);
        }

        template<typename F>
        filter_impl::filter_not_impl<typename F::table_type, F> filter_not(const F& f){
            return filter_impl::filter_not_impl<typename F::table_type, F>(f);
        }

        template<typename HT>
        filter_impl::subtract_impl<HT> subtract(const HT& ht){
            return filter_impl::subtract_impl<HT>(ht);
        }

        template<typename HT, typename HT2, typename ...Args>
        filter_impl::subtract_many_impl<HT, HT, HT2, Args...> subtract(const HT& h, const HT2& h2, Args&&... args){
            return filter_impl::subtract_many_impl<HT, HT, HT2, Args...>(h, h2, std::forward<Args>(args)...);
        }

        template<typename HT>
        filter_impl::intersect_impl<HT> intersect(const HT& ht){
            return filter_impl::intersect_impl<HT>(ht);
        }

        template<typename HT, typename HT2, typename ...Args>
        filter_impl::intersect_many_impl<HT, HT, HT2, Args...> intersect(const HT& h, const HT2& h2, Args&&... args){
            return filter_impl::intersect_many_impl<HT, HT, HT2, Args...>(h, h2, std::forward<Args>(args)...);
        }


    }

    /* --------------------------------------------------------------------------------------
                                        SET OPERATIONS
       -------------------------------------------------------------------------------------- */

    // ------------------------------ SET -------------------------------

    // ---------------- UNION ------------------
    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_set<V, Hash, Equal, Alloc> operator|(const hash_table_set<V, Hash, Equal, Alloc>& lhs, const hash_table_set<V, Hash, Equal, Alloc>& rhs){
        if(lhs.size() >= rhs.size()){
            hash_table_set<V, Hash, Equal, Alloc> result = lhs.copy(no_filter<V>(), CopyPolicy::duplicate_source);
            result.merge_from(rhs);
            return result;
        } else {
            hash_table_set<V, Hash, Equal, Alloc> result = rhs.copy(no_filter<V>(), CopyPolicy::duplicate_source);
            result.merge_from(lhs);
            return result;
        }
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_set<V, Hash, Equal, Alloc> operator|(hash_table_set<V, Hash, Equal, Alloc>&& lhs, const hash_table_set<V, Hash, Equal, Alloc>& rhs){
        lhs.merge_from(rhs);
        return std::move(lhs);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_set<V, Hash, Equal, Alloc> operator|(const hash_table_set<V, Hash, Equal, Alloc>& lhs, hash_table_set<V, Hash, Equal, Alloc>&& rhs){
        rhs.merge_from(lhs);
        return std::move(rhs);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_set<V, Hash, Equal, Alloc> operator|(hash_table_set<V, Hash, Equal, Alloc>&& lhs, hash_table_set<V, Hash, Equal, Alloc>&& rhs){
        if(lhs.size() >= rhs.size()){
            lhs.merge_from(rhs);
            return std::move(lhs);
        } else {
            rhs.merge_from(lhs);
            return std::move(rhs);
        }
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_list_set<V, Hash, Equal, Alloc> operator|(const hash_table_list_set<V, Hash, Equal, Alloc>& lhs, const hash_table_list_set<V, Hash, Equal, Alloc>& rhs){
        hash_table_list_set<V, Hash, Equal, Alloc> result = lhs.copy(no_filter<V>(), CopyPolicy::duplicate_source);
        result.merge_from(rhs);
        return result;
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_list_set<V, Hash, Equal, Alloc> operator|(hash_table_list_set<V, Hash, Equal, Alloc>&& lhs, const hash_table_list_set<V, Hash, Equal, Alloc>& rhs){
        lhs.merge_from(rhs);
        return std::move(lhs);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_list_set<V, Hash, Equal, Alloc> operator|(const hash_table_list_set<V, Hash, Equal, Alloc>& lhs, hash_table_list_set<V, Hash, Equal, Alloc>&& rhs){
        hash_table_list_set<V, Hash, Equal, Alloc> result = lhs.copy(no_filter<V>(), CopyPolicy::duplicate_source);
        result.merge_from(std::move(rhs));
        return result;
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_list_set<V, Hash, Equal, Alloc> operator|(hash_table_list_set<V, Hash, Equal, Alloc>&& lhs, hash_table_list_set<V, Hash, Equal, Alloc>&& rhs){
        lhs.merge_from(std::move(rhs));
        return std::move(lhs);
    }

    // ---------------- INTERSECT ------------------
    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_set<V, Hash, Equal, Alloc> operator&(const hash_table_set<V, Hash, Equal, Alloc>& lhs, const hash_table_set<V, Hash, Equal, Alloc>& rhs){
        if(lhs.size() <= rhs.size()){
            return lhs.copy([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) >= 0; }, CopyPolicy::duplicate_source);
        } else {
            return rhs.copy([&lhs](hash_type hash, const V& value){return lhs.find_index_h(hash, value) >= 0; }, CopyPolicy::duplicate_source);
        }
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_set<V, Hash, Equal, Alloc> operator&(hash_table_set<V, Hash, Equal, Alloc>&& lhs, const hash_table_set<V, Hash, Equal, Alloc>& rhs){
        lhs.self_filter([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) >= 0; });
        return std::move(lhs);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_set<V, Hash, Equal, Alloc> operator&(const hash_table_set<V, Hash, Equal, Alloc>& lhs, hash_table_set<V, Hash, Equal, Alloc>&& rhs){
        rhs.self_filter([&lhs](hash_type hash, const V& value){return lhs.find_index_h(hash, value) >= 0; });
        return std::move(rhs);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_set<V, Hash, Equal, Alloc> operator&(hash_table_set<V, Hash, Equal, Alloc>&& lhs, hash_table_set<V, Hash, Equal, Alloc>&& rhs){
        if(lhs.size() <= rhs.size()){
            lhs.self_filter([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) >= 0; });
            return std::move(lhs);
        } else {
            rhs.self_filter([&lhs](hash_type hash, const V& value){return lhs.find_index_h(hash, value) >= 0; });
            return std::move(rhs);
        }
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_list_set<V, Hash, Equal, Alloc> operator&(const hash_table_list_set<V, Hash, Equal, Alloc>& lhs, const hash_table_list_set<V, Hash, Equal, Alloc>& rhs){
        return lhs.copy([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) >= 0; }, CopyPolicy::duplicate_source);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_list_set<V, Hash, Equal, Alloc> operator&(hash_table_list_set<V, Hash, Equal, Alloc>&& lhs, const hash_table_list_set<V, Hash, Equal, Alloc>& rhs){
        lhs.self_filter([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) >= 0; });
        return std::move(lhs);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_list_set<V, Hash, Equal, Alloc> operator&(const hash_table_list_set<V, Hash, Equal, Alloc>& lhs, hash_table_list_set<V, Hash, Equal, Alloc>&& rhs){
        return lhs.copy([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) >= 0; }, CopyPolicy::duplicate_source);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_list_set<V, Hash, Equal, Alloc> operator&(hash_table_list_set<V, Hash, Equal, Alloc>&& lhs, hash_table_list_set<V, Hash, Equal, Alloc>&& rhs){
        lhs.self_filter([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) >= 0; });
        return std::move(lhs);
    }

    // ---------------- EXCLUSIVE OR ------------------
    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_set<V, Hash, Equal, Alloc> operator^(const hash_table_set<V, Hash, Equal, Alloc>& lhs, const hash_table_set<V, Hash, Equal, Alloc>& rhs){
        if(lhs.size() >= rhs.size()){
            hash_table_set<V, Hash, Equal, Alloc> result(lhs.size() + rhs.size(), static_cast<const Alloc&>(lhs));
            lhs.copy_into_and_replace(result, [&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) < 0; }, CopyPolicy::keep_target_capacity);
            rhs.iterate([&result, &lhs](hash_type hash, const V& value){
                if(lhs.find_index_h(hash, value) < 0)
                    result.insert_value_h(hash, value);
            });
            return result;
        } else {
            hash_table_set<V, Hash, Equal, Alloc> result(lhs.size() + rhs.size(), static_cast<const Alloc&>(rhs));
            rhs.copy_into_and_replace(result, [&lhs](hash_type hash, const V& value){return lhs.find_index_h(hash, value) < 0; }, CopyPolicy::keep_target_capacity);
            lhs.iterate([&result, &rhs](hash_type hash, const V& value){
                if(rhs.find_index_h(hash, value) < 0)
                    result.insert_value_h(hash, value);
            });
            return result;
        }
    }


    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_list_set<V, Hash, Equal, Alloc> operator^(const hash_table_list_set<V, Hash, Equal, Alloc>& lhs, const hash_table_list_set<V, Hash, Equal, Alloc>& rhs){
        hash_table_list_set<V, Hash, Equal, Alloc> result(lhs.size() + rhs.size(), static_cast<const Alloc&>(lhs));
        lhs.copy_into_and_replace(result, [&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) < 0; }, CopyPolicy::keep_target_capacity);
        rhs.iterate([&result, &lhs](hash_type hash, const V& value){
            if(lhs.find_index_h(hash, value) < 0)
                result.insert_value_h(hash, value);
        });
        return result;
    }

    // ---------------- SUBTRACT ------------------
    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_set<V, Hash, Equal, Alloc> operator-(const hash_table_set<V, Hash, Equal, Alloc>& lhs, const hash_table_set<V, Hash, Equal, Alloc>& rhs){
        return lhs.copy([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) < 0; }, CopyPolicy::duplicate_source);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_set<V, Hash, Equal, Alloc> operator-(hash_table_set<V, Hash, Equal, Alloc>&& lhs, const hash_table_set<V, Hash, Equal, Alloc>& rhs){
        lhs.self_filter([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) < 0; });
        return std::move(lhs);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_set<V, Hash, Equal, Alloc> operator-(const hash_table_set<V, Hash, Equal, Alloc>& lhs, hash_table_set<V, Hash, Equal, Alloc>&& rhs){
        return lhs.copy([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) < 0; }, CopyPolicy::duplicate_source);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_set<V, Hash, Equal, Alloc> operator-(hash_table_set<V, Hash, Equal, Alloc>&& lhs, hash_table_set<V, Hash, Equal, Alloc>&& rhs){
        lhs.self_filter([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) < 0; });
        return std::move(lhs);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_list_set<V, Hash, Equal, Alloc> operator-(const hash_table_list_set<V, Hash, Equal, Alloc>& lhs, const hash_table_list_set<V, Hash, Equal, Alloc>& rhs){
        return lhs.copy([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) < 0; }, CopyPolicy::duplicate_source);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_list_set<V, Hash, Equal, Alloc> operator-(hash_table_list_set<V, Hash, Equal, Alloc>&& lhs, const hash_table_list_set<V, Hash, Equal, Alloc>& rhs){
        lhs.self_filter([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) < 0; });
        return std::move(lhs);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_list_set<V, Hash, Equal, Alloc> operator-(const hash_table_list_set<V, Hash, Equal, Alloc>& lhs, hash_table_list_set<V, Hash, Equal, Alloc>&& rhs){
        return lhs.copy([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) < 0; }, CopyPolicy::duplicate_source);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    hash_table_list_set<V, Hash, Equal, Alloc> operator-(hash_table_list_set<V, Hash, Equal, Alloc>&& lhs, hash_table_list_set<V, Hash, Equal, Alloc>&& rhs){
        lhs.self_filter([&rhs](hash_type hash, const V& value){return rhs.find_index_h(hash, value) < 0; });
        return std::move(lhs);
    }

    // ------------------------------ MAP -------------------------------

    // ---------------- UNION ------------------
    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator|(const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        if(lhs.size() >= rhs.size()){
            hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> result = lhs.copy(no_filter<typename KvpAdapter::pair_type>(), CopyPolicy::duplicate_source);
            result.merge_from(rhs);
            return result;
        } else {
            hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> result = rhs.copy(no_filter<typename KvpAdapter::pair_type>(), CopyPolicy::duplicate_source);
            result.merge_from(lhs);
            return result;
        }
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator|(hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& lhs, const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        lhs.merge_from(rhs);
        return std::move(lhs);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator|(const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& rhs){
        rhs.merge_from(lhs);
        return std::move(rhs);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator|(hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& lhs, hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& rhs){
        if(lhs.size() >= rhs.size()){
            lhs.merge_from(rhs);
            return std::move(lhs);
        } else {
            rhs.merge_from(lhs);
            return std::move(rhs);
        }
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator|(const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> result = lhs.copy(no_filter<typename KvpAdapter::pair_type>(), CopyPolicy::duplicate_source);
        result.merge_from(rhs);
        return result;
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator|(hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& lhs, const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        lhs.merge_from(rhs);
        return std::move(lhs);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator|(const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& rhs){
        hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> result = lhs.copy(no_filter<typename KvpAdapter::pair_type>(), CopyPolicy::duplicate_source);
        result.merge_from(std::move(rhs));
        return result;
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator|(hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& lhs, hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& rhs){
        lhs.merge_from(std::move(rhs));
        return std::move(lhs);
    }

    // ---------------- INTERSECT ------------------
    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator&(const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        if(lhs.size() <= rhs.size()){
            return lhs.copy([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) >= 0; }, CopyPolicy::duplicate_source);
        } else {
            return rhs.copy([&lhs](hash_type hash, const typename KvpAdapter::pair_type& value){return lhs.find_index_h(hash, value) >= 0; }, CopyPolicy::duplicate_source);
        }
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator&(hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& lhs, const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        lhs.self_filter([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) >= 0; });
        return std::move(lhs);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator&(const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& rhs){
        rhs.self_filter([&lhs](hash_type hash, const typename KvpAdapter::pair_type& value){return lhs.find_index_h(hash, value) >= 0; });
        return std::move(rhs);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator&(hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& lhs, hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& rhs){
        if(lhs.size() <= rhs.size()){
            lhs.self_filter([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) >= 0; });
            return std::move(lhs);
        } else {
            rhs.self_filter([&lhs](hash_type hash, const typename KvpAdapter::pair_type& value){return lhs.find_index_h(hash, value) >= 0; });
            return std::move(rhs);
        }
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator&(const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        return lhs.copy([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) >= 0; }, CopyPolicy::duplicate_source);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator&(hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& lhs, const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        lhs.self_filter([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) >= 0; });
        return std::move(lhs);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator&(const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& rhs){
        return lhs.copy([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) >= 0; }, CopyPolicy::duplicate_source);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator&(hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& lhs, hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& rhs){
        lhs.self_filter([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) >= 0; });
        return std::move(lhs);
    }

    // ---------------- EXCLUSIVE OR ------------------
    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator^(const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        if(lhs.size() >= rhs.size()){
            hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> result(lhs.size() + rhs.size(), static_cast<const Alloc&>(lhs));
            lhs.copy_into_and_replace(result, [&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) < 0; }, CopyPolicy::keep_target_capacity);
            rhs.iterate([&result, &lhs](hash_type hash, const typename KvpAdapter::pair_type& value){
                if(lhs.find_index_h(hash, value) < 0)
                    result.insert_value_h(hash, value);
            });
            return result;
        } else {
            hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> result(lhs.size() + rhs.size(), static_cast<const Alloc&>(rhs));
            rhs.copy_into_and_replace(result, [&lhs](hash_type hash, const typename KvpAdapter::pair_type& value){return lhs.find_index_h(hash, value) < 0; }, CopyPolicy::keep_target_capacity);
            lhs.iterate([&result, &rhs](hash_type hash, const typename KvpAdapter::pair_type& value){
                if(rhs.find_index_h(hash, value) < 0)
                    result.insert_value_h(hash, value);
            });
            return result;
        }
    }


    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator^(const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> result(lhs.size() + rhs.size(), static_cast<const Alloc&>(lhs));
        lhs.copy_into_and_replace(result, [&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) < 0; }, CopyPolicy::keep_target_capacity);
        rhs.iterate([&result, &lhs](hash_type hash, const typename KvpAdapter::pair_type& value){
            if(lhs.find_index_h(hash, value) < 0)
                result.insert_value_h(hash, value);
        });
        return result;
    }

    // ---------------- SUBTRACT ------------------
    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator-(const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        return lhs.copy([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) < 0; }, CopyPolicy::duplicate_source);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator-(hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& lhs, const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        lhs.self_filter([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) < 0; });
        return std::move(lhs);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator-(const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& rhs){
        return lhs.copy([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) < 0; }, CopyPolicy::duplicate_source);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator-(hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& lhs, hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& rhs){
        lhs.self_filter([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) < 0; });
        return std::move(lhs);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator-(const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        return lhs.copy([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) < 0; }, CopyPolicy::duplicate_source);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator-(hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& lhs, const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        lhs.self_filter([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) < 0; });
        return std::move(lhs);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator-(const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& rhs){
        return lhs.copy([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) < 0; }, CopyPolicy::duplicate_source);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc> operator-(hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& lhs, hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>&& rhs){
        lhs.self_filter([&rhs](hash_type hash, const typename KvpAdapter::pair_type& value){return rhs.find_index_h(hash, value) < 0; });
        return std::move(lhs);
    }

}


/* --------------------------------------------------------------------------------------
                                    STANDARD AND COMMON OPERATIONS
   -------------------------------------------------------------------------------------- */

namespace ghash{
    template<typename V, typename Hash, typename Equal, typename Alloc>
    bool operator==(const hash_table_set<V, Hash, Equal, Alloc>& lhs, const hash_table_set<V, Hash, Equal, Alloc>& rhs){
        return lhs.equals(rhs);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    bool operator!=(const hash_table_set<V, Hash, Equal, Alloc>& lhs, const hash_table_set<V, Hash, Equal, Alloc>& rhs){
        return !lhs.equals(rhs);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    bool operator==(const hash_table_list_set<V, Hash, Equal, Alloc>& lhs, const hash_table_list_set<V, Hash, Equal, Alloc>& rhs){
        return lhs.equals(rhs);
    }

    template<typename V, typename Hash, typename Equal, typename Alloc>
    bool operator!=(const hash_table_list_set<V, Hash, Equal, Alloc>& lhs, const hash_table_list_set<V, Hash, Equal, Alloc>& rhs){
        return !lhs.equals(rhs);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    bool operator==(const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        return lhs.equals(rhs);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    bool operator!=(const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, const hash_table_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        return !lhs.equals(rhs);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    bool operator==(const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        return lhs.equals(rhs);
    }

    template<typename K, typename V, typename KvpAdapter, typename Hash, typename EqualKey, typename EqualValue, typename Alloc>
    bool operator!=(const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& lhs, const hash_table_list_map<K, V, KvpAdapter, Hash, EqualKey, EqualValue, Alloc>& rhs){
        return !lhs.equals(rhs);
    }
}

namespace std{
    template<typename V, typename A>
    void swap(ghash::hash_table_container<V, A>& lhs, ghash::hash_table_container<V, A>& rhs) noexcept{
        lhs.swap(rhs);
    }
    template<typename V, typename H, typename E, typename A>
    void swap(ghash::hash_table_set<V, H, E, A>& lhs, ghash::hash_table_set<V, H, E, A>& rhs) noexcept{
        lhs.swap(rhs);
    }
    template<typename K, typename V, typename C, typename H, typename E, typename A>
    void swap(ghash::hash_table_map<K, V, C, H, E, A>& lhs, ghash::hash_table_map<K, V, C, H, E, A>& rhs) noexcept{
        lhs.swap(rhs);
    }

    template<typename V, typename H, typename A> void swap(ghash::hash_table_list_container<V, H, A>& lhs, ghash::hash_table_list_container<V, H, A>& rhs) noexcept{
        lhs.swap(rhs);
    }
    template<typename V, typename H, typename E, typename A>
    void swap(ghash::hash_table_list_set<V, H, E, A>& lhs, ghash::hash_table_list_set<V, H, E, A>& rhs) noexcept{
        lhs.swap(rhs);
    }
    template<typename K, typename V, typename C, typename H, typename E, typename A>
    void swap(ghash::hash_table_list_map<K, V, C, H, E, A>& lhs, ghash::hash_table_list_map<K, V, C, H, E, A>& rhs) noexcept{
        lhs.swap(rhs);
    }
}



/* --------------------------------------------------------------------------------------
                                    STD HASH TABLE ALTERNATIVES
   -------------------------------------------------------------------------------------- */

namespace ghash{
    template<typename V, typename TableType=hash_table_set<V>>
    class hash_set{
    public:
        using table_type = TableType;
        using key_type = typename TableType::value_type;
        using value_type = typename TableType::value_type;
        using size_type = size_t;
        using allocator = typename table_type::allocator;
        using iterator = typename table_type::iterator;
        using const_iterator = typename table_type::const_iterator;
        using reverse_iterator = typename table_type::reverse_iterator;
        using const_reverse_iterator = typename table_type::const_reverse_iterator;

        explicit hash_set(size_t capacity=0, allocator&& alloc=allocator()) : hash_table(capacity, std::move(alloc)) {}
        explicit hash_set(size_t capacity, const allocator& alloc) : hash_table(capacity, alloc) {}
        hash_set(const hash_set& src) : hash_table(src.hash_table) {}
        hash_set(hash_set&& src) : hash_table(std::move(src.hash_table)) {}
        hash_set& operator=(const hash_set& rhs) { if(this!=&rhs) {hash_table = rhs.hash_table;} return *this; }
        hash_set& operator=(hash_set&& rhs) { if(this!=&rhs) {hash_table = std::move(rhs.hash_table);} return *this; }
        hash_set(const table_type& src) : hash_table(src) {}
        hash_set(table_type&& src) : hash_table(std::move(src)) {}
        hash_set& operator=(const table_type& rhs) { if(&hash_table!=&rhs) {hash_table = rhs;} return *this; }
        hash_set& operator=(table_type&& rhs) { if(&hash_table!=&rhs) {hash_table = std::move(rhs);} return *this; }
        hash_set(std::initializer_list<V> elms, size_t capacity=0, const allocator& alloc=allocator()) : hash_table(capacity, alloc) {
            hash_table.insert_many_il(elms);
        }
        template<typename InputIterator> hash_set(InputIterator start_iterator, InputIterator end_iterator, size_t capacity=0, const allocator& alloc=allocator()) : hash_table(capacity, alloc){
            hash_table.insert_many_it(std::forward<InputIterator>(start_iterator), std::forward<InputIterator>(end_iterator));
        }

        void rehash(size_t capacity, bool force_rehash=true){
            hash_table.set_capacity(capacity, force_rehash);
        }

        void reserve(size_t capacity){
            hash_table.expand_capacity(capacity);
        }

        void swap(hash_set& other){
            std::swap(hash_table, other.hash_table);
        }

        template<typename V2, typename TableType2>friend bool operator==(const hash_set<V2, TableType2>& lhs, const hash_set<V2, TableType2>& rhs);
        template<typename V2, typename TableType2>friend bool operator!=(const hash_set<V2, TableType2>& lhs, const hash_set<V2, TableType2>& rhs);

        hash_set& merge(const hash_set& source, OverlappingPolicy overlapping_policy=OverlappingPolicy::ignore_duplicates){
            hash_table.merge_from(source.hash_table, OverlappingPolicy::ignore_duplicates);
            return *this;
        }

        hash_set& merge(hash_set&& source, OverlappingPolicy overlapping_policy=OverlappingPolicy::ignore_duplicates){
            hash_table.merge_from(std::move(source.hash_table), OverlappingPolicy::ignore_duplicates);
            return *this;
        }

        iterator begin(){ return hash_table.begin(); }
        const_iterator begin()const{ return hash_table.cbegin(); }
        const_iterator cbegin()const{ return hash_table.cbegin(); }

        reverse_iterator rbegin(){ return hash_table.rbegin(); }
        const_reverse_iterator rbegin()const{ return hash_table.crbegin(); }
        const_reverse_iterator crbegin()const{ return hash_table.crbegin(); }

        iterator end(){ return hash_table.end(); }
        const_iterator end()const{ return hash_table.cend(); }
        const_iterator cend()const{ return hash_table.cend(); }

        reverse_iterator rend(){ return hash_table.rend(); }
        const_reverse_iterator rend()const{ return hash_table.crend(); }
        const_reverse_iterator crend()const{ return hash_table.crend(); }

        bool empty(){ return hash_table.size() > 0; }

        size_type size() const noexcept { return hash_table.size(); }

        void clear(){ hash_table.clear(); }

        allocator get_allocator() const noexcept{
            return allocator(static_cast<allocator*>(this));
        }

        size_type count(const key_type& value) const{
            return (hash_table.find_index(value) >= 0) ? 1 : 0;
        }

        const_iterator find(const key_type& value) const{
            index_type index = hash_table.find_index(value);
            if(index >= 0){
                return hash_table.at_index(index);
            } else {
                return end();
            }
        }

        iterator find(const key_type& value){
            index_type index = hash_table.find_index(value);
            if(index >= 0){
                return hash_table.at_index(index);
            } else {
                return end();
            }
        }

        bool contains(const key_type& value) const{
            return hash_table.find_index(value) >= 0;
        }

        std::pair<iterator, iterator> equal_range(const key_type& value){
            index_type index = hash_table.find_index(value);
            if(index >= 0){
                return {hash_table.at_index(index), hash_table.at_index(index)};
            } else {
                return {end(), end()};
            }
        }

        std::pair<iterator, iterator> equal_range(const key_type& value) const{
            index_type index = hash_table.find_index(value);
            if(index >= 0){
                return {hash_table.at_index(index), hash_table.at_index(index)};
            } else {
                return {end(), end()};
            }
        }

        std::pair<iterator, bool> insert(const value_type& value){
            insert_result result = hash_table.insert_or_find_value(value);
            return {hash_table.at_index(result.get_index()), result.is_inserted()};
        }

        std::pair<iterator, bool> insert(value_type&& value){
            insert_result result = hash_table.insert_or_find_value(std::move(value));
            return {hash_table.at_index(result.get_index()), result.is_inserted()};
        }

        void insert(std::initializer_list<value_type> il){
            hash_table.insert_many_il(il);
        }

        template<class InputIterator> void insert(InputIterator it_start, InputIterator it_end){
            hash_table.insert_many_it(it_start, it_end);
        }

        template< class... Args > std::pair<iterator, bool> emplace( Args&&... args ){
            insert_result result = hash_table.emplace_or_find_value(std::forward<Args>(args)...);
            return {hash_table.at_index(result.get_index()), result.is_inserted()};
        }

        size_type erase(const key_type& value){
            return hash_table.erase_value(value) >= 0 ? 1 : 0;
        }

        iterator erase(iterator it){
            return hash_table.erase_value_and_get_next(*it);
        }

        iterator erase(const_iterator it){
            return hash_table.erase_value_and_get_next(*it);
        }

        iterator erase(const_iterator start_it, const_iterator end_it){
            iterator res = end();
            for(auto it = start_it; it!=end_it; ++it){
                res = hash_table.erase_value_and_get_next(*it);
                if(res == end())
                    return res;
            }
            return res;
        }

        template<typename F>
        size_t erase_if(F func){
            size_t old_size = hash_table.size();
            hash_table.self_filter([&func](hash_type, const value_type& value){ return !func(value);});
            return old_size - hash_table.size();
        }

        typename TableType::hash_function hash_function() { return TableType::hash_function(); }
        typename TableType::equality_function key_eq() { return TableType::equality_function(); }

    //private:
        TableType hash_table;
    };


    template<typename K, typename V, typename TableType=hash_table_map<K, V>>
    class hash_map{
    public:
        using table_type = TableType;
        using key_type = typename TableType::key_type;
        using value_type = typename TableType::pair_type;
        using mapped_type = typename TableType::value_type;
        using size_type = size_t;
        using allocator = typename table_type::allocator;
        using iterator = typename table_type::iterator;
        using const_iterator = typename table_type::const_iterator;
        using reverse_iterator = typename table_type::reverse_iterator;
        using const_reverse_iterator = typename table_type::const_reverse_iterator;

        explicit hash_map(size_t capacity=0, allocator&& alloc=allocator()) : hash_table(capacity, std::move(alloc)) {}
        explicit hash_map(size_t capacity, const allocator& alloc) : hash_table(capacity, alloc) {}
        hash_map(const hash_map& src) : hash_table(src.hash_table) {}
        hash_map(hash_map&& src) : hash_table(std::move(src.hash_table)) {}
        hash_map& operator=(const hash_map& rhs) { if(this!=&rhs) {hash_table = rhs.hash_table;} return *this; }
        hash_map& operator=(hash_map&& rhs) { if(this!=&rhs) {hash_table = std::move(rhs.hash_table);} return *this; }
        hash_map(const table_type& src) : hash_table(src) {}
        hash_map(table_type&& src) : hash_table(std::move(src)) {}
        hash_map& operator=(const table_type& rhs) { if(&hash_table!=&rhs) {hash_table = rhs;} return *this; }
        hash_map& operator=(table_type&& rhs) { if(&hash_table!=&rhs) {hash_table = std::move(rhs);} return *this; }
        hash_map(std::initializer_list<typename table_type::pair_type> elms, size_t capacity=0, const allocator& alloc=allocator()) : hash_table(capacity, alloc) {
            hash_table.insert_many_il(elms);
        }
        template<typename InputIterator> hash_map(InputIterator start_iterator, InputIterator end_iterator, size_t capacity=0, const allocator& alloc=allocator()) : hash_table(capacity, alloc){
            hash_table.insert_many_it(std::forward<InputIterator>(start_iterator), std::forward<InputIterator>(end_iterator));
        }

        void rehash(size_t capacity, bool force_rehash=true){
            hash_table.set_capacity(capacity, force_rehash);
        }

        void reserve(size_t capacity){
            hash_table.expand_capacity(capacity);
        }

        void swap(hash_map& other){
            std::swap(hash_table, other.hash_table);
        }

        template<typename K2, typename V2, typename TableType2>friend bool operator==(const hash_map<K2, V2, TableType2>& lhs, const hash_map<K2, V2, TableType2>& rhs);
        template<typename K2, typename V2, typename TableType2>friend bool operator!=(const hash_map<K2, V2, TableType2>& lhs, const hash_map<K2, V2, TableType2>& rhs);

        hash_map& merge(const hash_map& source, OverlappingPolicy overlapping_policy=OverlappingPolicy::ignore_duplicates){
            hash_table.merge_from(source.hash_table, overlapping_policy);
            return *this;
        }

        hash_map& merge(hash_map&& source, OverlappingPolicy overlapping_policy=OverlappingPolicy::ignore_duplicates){
            hash_table.merge_from(std::move(source.hash_table), OverlappingPolicy::ignore_duplicates);
            return *this;
        }

        iterator begin(){ return hash_table.begin(); }
        const_iterator begin()const{ return hash_table.cbegin(); }
        const_iterator cbegin()const{ return hash_table.cbegin(); }

        reverse_iterator rbegin(){ return hash_table.rbegin(); }
        const_reverse_iterator rbegin()const{ return hash_table.crbegin(); }
        const_reverse_iterator crbegin()const{ return hash_table.crbegin(); }

        iterator end(){ return hash_table.end(); }
        const_iterator end()const{ return hash_table.cend(); }
        const_iterator cend()const{ return hash_table.cend(); }

        reverse_iterator rend(){ return hash_table.rend(); }
        const_reverse_iterator rend()const{ return hash_table.crend(); }
        const_reverse_iterator crend()const{ return hash_table.crend(); }

        bool empty(){ return hash_table.size() > 0; }

        size_type size() const noexcept { return hash_table.size();}

        void clear(){ hash_table.clear(); }

        allocator get_allocator() const noexcept{
            return allocator(static_cast<allocator*>(this));
        }

        mapped_type& at(const key_type& key){
            index_type index = hash_table.find_index(key);
            if(index < 0){
                throw std::out_of_range("hash_map::at");
            }
            return hash_table.get_value(index);
        }

        const mapped_type& at(const key_type& key) const {
            index_type index = hash_table.find_index(key);
            if(index < 0){
                throw std::out_of_range("hash_map::at");
            }
            return const_cast<const mapped_type&> (hash_table.get_value(index));
        }

        mapped_type& operator[](const key_type& key){
            insert_result result = hash_table.emplace_or_find_value(key);
            return TableType::kvp_adapter().value(hash_table.get_value(result.get_index()));
        }

        mapped_type& operator[](key_type&& key){
            insert_result result = hash_table.emplace_or_find_value(std::move(key));
            return TableType::kvp_adapter().value(hash_table.get_value(result.get_index()));
        }

        size_type count(const key_type& key){
            return (hash_table.find_index(key) >= 0) ? 1 : 0;
        }

        const_iterator find(const key_type& key) const{
            index_type index = hash_table.find_index(key);
            if(index >= 0){
                return hash_table.at_index(index);
            } else {
                return end();
            }
        }

        iterator find(const key_type& key){
            index_type index = hash_table.find_index(key);
            if(index >= 0){
                return hash_table.at_index(index);
            } else {
                return end();
            }
        }

        bool contains(const key_type& key){
            return hash_table.find_index(key) >= 0;
        }

        std::pair<iterator, iterator> equal_range(const key_type& key){
            index_type index = hash_table.find_index(key);
            if(index >= 0){
                return {hash_table.at_index(index), hash_table.at_index(index)};
            } else {
                return {end(), end()};
            }
        }

        std::pair<iterator, iterator> equal_range(const key_type& key) const{
            index_type index = hash_table.find_index(key);
            if(index >= 0){
                return {hash_table.at_index(index), hash_table.at_index(index)};
            } else {
                return {end(), end()};
            }
        }

        std::pair<iterator, bool> insert(const value_type& value){
            insert_result result = hash_table.insert_or_find_value(value);
            return {hash_table.at_index(result.get_index()), result.is_inserted()};
        }

        std::pair<iterator, bool> insert(value_type&& value){
            insert_result result = hash_table.insert_value(std::move(value));
            return {hash_table.at_index(result.get_index()), result.is_inserted()};
        }

        template<typename Pair, typename std::enable_if<std::is_constructible<value_type, Pair&&>::value, void*>::type = nullptr>
        std::pair<iterator, bool> insert(Pair&& value){
            insert_result result = hash_table.insert_or_find_value(std::forward<Pair>(value));
            return {hash_table.at_index(result.get_index()), result.is_inserted()};
        }

        void insert(std::initializer_list<value_type> il){
            hash_table.insert_many_il(il);
        }

        template<class InputIterator> void insert(InputIterator it_start, InputIterator it_end){
            hash_table.insert_many_it(it_start, it_end);
        }

        template< class... Args > std::pair<iterator, bool> emplace(Args&&... args ){
            insert_result result = hash_table.insert_or_find_value(value_type(std::forward<Args>(args)...));
            return {hash_table.at_index(result.get_index()), result.is_inserted()};
        }

        template< class... Args > std::pair<iterator, bool> try_emplace(const key_type& key, Args&&... args){
            insert_result result = hash_table.emplace_or_find_value(key, std::forward<Args>(args)...);
            return {hash_table.at_index(result.get_index()), result.is_inserted()};
        }

        template< class... Args > std::pair<iterator, bool> try_emplace(key_type&& key, Args&&... args){
            insert_result result = hash_table.emplace_or_find_value(std::move(key), std::forward<Args>(args)...);
            return {hash_table.at_index(result.get_index()), result.is_inserted()};
        }

        template< class M >
        std::pair<iterator, bool> insert_or_assign(const key_type& key, M&& value){
            insert_result result = hash_table.emplace_or_replace_value(key, std::forward<M>(value));
            return {hash_table.at_index(result.get_index()), result.is_inserted()};
        }

        template< class M >
        std::pair<iterator, bool> insert_or_assign(key_type&& key, M&& value){
            insert_result result = hash_table.emplace_or_replace_value(std::move(key), std::forward<M>(value));
            return {hash_table.at_index(result.get_index()), result.is_inserted()};
        }

        size_type erase(const key_type& key){
            return hash_table.erase_value(key) >= 0 ? 1 : 0;
        }

        iterator erase(iterator it){
            return hash_table.erase_value_and_get_next(typename TableType::kvp_adapter().key(*it));
        }

        iterator erase(const_iterator it){
            return hash_table.erase_value_and_get_next(*it);
        }

        iterator erase(const_iterator start_it, const_iterator end_it){
            iterator res = end();
            for(auto it = start_it; it!=end_it; ++it){
                res = hash_table.erase_value_and_get_next(*it);
                if(res == end())
                    return res;
            }
            return res;
        }

        template<typename F>
        size_t erase_if(F func){
            size_t old_size = hash_table.size();
            hash_table.self_filter([&func](hash_type, const value_type& value){ return !func(value);});
            return old_size - hash_table.size();
        }

        typename TableType::hash_function hash_function() { return TableType::hash_function(); }
        typename TableType::key_equality_function key_eq() { return TableType::key_equality_function(); }

    //private:
        TableType hash_table;
    };

    template<typename V>
    using hash_list_set = hash_set<V, hash_table_list_set<V>>;

    template<typename K, typename V>
    using hash_list_map = hash_map<K, V, hash_table_list_map<K, V>>;

    template<typename V2, typename TableType2>inline bool operator==(const hash_set<V2, TableType2>& lhs, const hash_set<V2, TableType2>& rhs){
        return lhs.hash_table.equals(rhs.hash_table);
    }
    template<typename V2, typename TableType2>inline bool operator!=(const hash_set<V2, TableType2>& lhs, const hash_set<V2, TableType2>& rhs){
        return !lhs.hash_table.equals(rhs.hash_table);
    }

    template<typename K2, typename V2, typename TableType2>inline bool operator==(const hash_map<K2, V2, TableType2>& lhs, const hash_map<K2, V2, TableType2>& rhs){
        return lhs.hash_table.equals(rhs.hash_table);
    }
    template<typename K2, typename V2, typename TableType2>inline bool operator!=(const hash_map<K2, V2, TableType2>& lhs, const hash_map<K2, V2, TableType2>& rhs){
        return !lhs.hash_table.equals(rhs.hash_table);
    }

}

namespace std{
    template<typename V, typename T> void swap(ghash::hash_set<V, T>& lhs, ghash::hash_set<V, T>& rhs) noexcept{
        lhs.swap(rhs);
    }
    template<typename K, typename V, typename T> void swap(ghash::hash_map<K, V, T>& lhs, ghash::hash_map<K, V, T>& rhs) noexcept{
        lhs.swap(rhs);
    }
}

#undef HT_METADATA_TYPE
#undef HT_HASH_TYPE
#undef HT_PADDING_SIZE
#undef HT_INDEX_TYPE
#undef HT_GET_METADATA_TABLE
#undef HT_GET_HASHSES_TABLE
#undef HT_GET_PADDING_TABLE
#undef HT_GET_VALUES_TABLE
#undef HT_GET_TABLES
#undef HT_METADATA_SIZE
#undef HT_VALUES_SIZE
#undef HT_TABLE_SIZE
#undef HT_VALUE_VALID
#undef HT_FIND_INDEX_BEGIN
#undef HT_FIND_INDEX_END
#undef HT_FIND_FREE_INDEX_BEGIN
#undef HT_FIND_FREE_INDEX_END
#undef HT_GET_GUARANTEED_FREE_INDEX
#undef HT_INSERT_ENTRY
#undef HT_DELETE_ENTRY

#endif // #ifdef __cplusplus

#endif // #ifdef HT_ONCE_GHASH_H
