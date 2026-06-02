/**
 * Copyright (c) 2011-2026 libbitcoin developers (see AUTHORS)
 *
 * This file is part of libbitcoin.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBBITCOIN_SYSTEM_MACHINE_SCRIPT_CHECKER_HPP
#define LIBBITCOIN_SYSTEM_MACHINE_SCRIPT_CHECKER_HPP

#include <bitcoin/system/crypto/crypto.hpp>
#include <bitcoin/system/data/data.hpp>
#include <bitcoin/system/define.hpp>
#include <bitcoin/system/error/error.hpp>
#include <bitcoin/system/hash/hash.hpp>

namespace libbitcoin {
namespace system {
namespace machine {

class BC_API script_checker
{
public:
    script_checker() NOEXCEPT = default;
    DELETE_COPY_MOVE_DESTRUCT(script_checker);

    virtual bool override_ecdsa_checksig_verify() const NOEXCEPT;

    virtual bool verify_schnorr_signature(
        const data_chunk& x_point,
        const hash_digest& hash,
        const ec_signature& signature) const NOEXCEPT;

    virtual error::op_error_t verify_locktime(
        bool input_final,
        uint64_t stack_locktime,
        uint32_t transaction_locktime) const NOEXCEPT;

    virtual error::op_error_t verify_sequence(
        uint32_t transaction_version,
        uint32_t stack_sequence,
        uint32_t input_sequence) const NOEXCEPT;
    
};

} // namespace machine
} // namespace system
} // namespace libbitcoin

#endif
