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

#include <bitcoin/system/machine/script_checker.hpp>
#include <bitcoin/system/chain/enums/magic_numbers.hpp>

namespace libbitcoin {
namespace system {
namespace machine {

bool script_checker::override_ecdsa_checksig_verify() const NOEXCEPT
{
    return false;
}

bool script_checker::verify_schnorr_signature(
    const data_chunk& x_point,
    const hash_digest& hash,
    const ec_signature& signature) const NOEXCEPT
{
    return schnorr::verify_signature(x_point, hash, signature);
}

error::op_error_t script_checker::verify_locktime(
    bool input_final,
    uint64_t stack_locktime,
    uint32_t transaction_locktime) const NOEXCEPT
{
    // The tx sequence is 0xffffffff.
    if (input_final)
        return error::op_check_locktime_verify1;

    // The stack locktime type differs from that of tx.
    if ((stack_locktime < chain::locktime_threshold) !=
        (transaction_locktime < chain::locktime_threshold))
        return error::op_check_locktime_verify3;

    // The stack locktime is greater than the tx locktime.
    if (stack_locktime > transaction_locktime)
        return error::op_check_locktime_verify4;

    // TODO: use sighash and key to generate signature in sign mode?
    return error::op_success;
}

error::op_error_t script_checker::verify_sequence(
    uint32_t transaction_version,
    uint32_t stack_sequence,
    uint32_t input_sequence) const NOEXCEPT
{
    using namespace chain;

    // The stack sequence is enabled and tx version less than 2.
    if (transaction_version < relative_locktime_min_version)
        return error::op_check_sequence_verify2;

    // The transaction sequence is disabled.
    if (get_right(input_sequence, relative_locktime_disabled_bit))
        return error::op_check_sequence_verify3;

    // The stack sequence type differs from that of tx input.
    if (get_right(stack_sequence, relative_locktime_time_locked_bit) !=
        get_right(input_sequence, relative_locktime_time_locked_bit))
        return error::op_check_sequence_verify4;

    // The unmasked stack sequence is greater than that of tx sequence.
    if (mask_left(stack_sequence, relative_locktime_mask_left) >
        mask_left(input_sequence, relative_locktime_mask_left))
        return error::op_check_sequence_verify5;

    return error::op_success;
}

} // namespace machine
} // namespace system
} // namespace libbitcoin
