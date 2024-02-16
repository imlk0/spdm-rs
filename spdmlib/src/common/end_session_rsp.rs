// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use codec::{Codec, Reader, Writer};

use crate::common::SpdmCodec;
use crate::common::SpdmContext;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::message::*;
use crate::protocol::SpdmRequestCapabilityFlags;
use crate::protocol::SpdmResponseCapabilityFlags;
use crate::watchdog::stop_watchdog;

use super::SpdmSessionState;

impl SpdmContext {
    pub fn handle_spdm_end_session<'a>(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        if self
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::HBEAT_CAP)
            && self
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::HBEAT_CAP)
        {
            stop_watchdog(session_id);
        }

        if let Some(session) = self.get_session_via_id(session_id) {
            if session.get_session_state() == SpdmSessionState::SpdmSessionEstablished {
                session.set_session_state(SpdmSessionState::SpdmSessionEndSessionReceived);
            } else if session.get_session_state() == SpdmSessionState::SpdmSessionEndSessionSent {
                session.set_session_state(SpdmSessionState::SpdmSessionEndSessionReceived);
                // TODO: should we call session.teardown() here?
            }
        }

        // TODO: change state of session, and keep this end session message
        let (_, rsp_slice) = self.write_spdm_end_session_ack(session_id, bytes, writer);
        (Ok(()), rsp_slice)
    }

    pub fn write_spdm_end_session_ack<'a>(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &'a mut Writer,
    ) -> (SpdmResult, Option<&'a [u8]>) {
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return (
                    Err(SPDM_STATUS_INVALID_MSG_FIELD),
                    Some(writer.used_slice()),
                );
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        let end_session_req = SpdmEndSessionRequestPayload::spdm_read(self, &mut reader);
        if let Some(end_session_req) = end_session_req {
            debug!("!!! end_session req : {:02x?}\n", end_session_req);
        } else {
            error!("!!! end_session req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_MSG_FIELD),
                Some(writer.used_slice()),
            );
        }

        self.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestEndSession,
            Some(session_id),
        );

        info!("send spdm end_session rsp\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseEndSessionAck,
            },
            payload: SpdmMessagePayload::SpdmEndSessionResponse(SpdmEndSessionResponsePayload {}),
        };
        let res = response.spdm_encode(self, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return (
                Err(SPDM_STATUS_INVALID_STATE_LOCAL),
                Some(writer.used_slice()),
            );
        }

        (Ok(()), Some(writer.used_slice()))
    }
}
