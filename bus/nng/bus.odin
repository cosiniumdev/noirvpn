// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package nng

// Event framing for the PUB socket.
// One event is one nng message:
//
//	<topic> SP <payload>
//
// - Topic: plain ASCII, no spaces, like "peer.connect". Payload: JSON.
// - A subscriber filters on a byte prefix of the whole message. "peer." matches
//   every topic that starts with it. "peer.connect " (with the space) matches
//   that one topic.
// - The event schema (fields, sequence number, version) is not defined here.

TOPIC_SEPARATOR :: ' '

// Publish one event.
publish :: proc(s: Socket, topic: string, payload: []byte, nonblock := false) -> Error {
	m, err := msg_new()
	if err != .None {
		return err
	}
	sep := [1]byte{TOPIC_SEPARATOR}
	err = msg_append(m, transmute([]byte)topic)
	if err == .None {
		err = msg_append(m, sep[:])
	}
	if err == .None {
		err = msg_append(m, payload)
	}
	if err == .None {
		err = send_msg(s, m, nonblock)
	}
	if err != .None {
		msg_free(m)
	}
	return err
}

// Split an event into its topic and payload. Both point into msg. With no
// separator the whole message is the topic and the payload is empty.
split_topic :: proc(msg: []byte) -> (topic: string, payload: []byte) {
	for b, i in msg {
		if b == TOPIC_SEPARATOR {
			return transmute(string)msg[:i], msg[i + 1:]
		}
	}
	return transmute(string)msg, nil
}
