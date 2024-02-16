// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::Writer;

use super::ResponderContext;
use crate::message::*;

impl ResponderContext {
    pub fn write_spdm_error(
        &mut self,
        error_code: SpdmErrorCode,
        error_data: u8,
        writer: &mut Writer,
    ) {
        self.common.write_spdm_error(error_code, error_data, writer)
    }
}
