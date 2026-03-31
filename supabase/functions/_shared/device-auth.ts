export interface DevicePollStateInput {
	nowMs: number;
	expiresAtIso: string;
	authorizedAt: string | null;
	userId: string | null;
	pilotApproved: boolean;
	exchangedAt: string | null;
}

export type DevicePollState =
	| { status: "expired"; httpStatus: 401; error: "device_code_expired" }
	| {
			status: "pending";
			httpStatus: 200;
			error: "authorization_pending";
	  }
	| { status: "forbidden"; httpStatus: 403; error: "pilot_not_approved" }
	| { status: "already_exchanged"; httpStatus: 409; error: "already_exchanged" }
	| { status: "approved"; httpStatus: 200 };

export function evaluateDevicePollState(input: DevicePollStateInput): DevicePollState {
	if (input.nowMs > Date.parse(input.expiresAtIso)) {
		return { status: "expired", httpStatus: 401, error: "device_code_expired" };
	}
	if (!input.authorizedAt || !input.userId) {
		return { status: "pending", httpStatus: 200, error: "authorization_pending" };
	}
	if (!input.pilotApproved) {
		return { status: "forbidden", httpStatus: 403, error: "pilot_not_approved" };
	}
	if (input.exchangedAt) {
		return { status: "already_exchanged", httpStatus: 409, error: "already_exchanged" };
	}
	return { status: "approved", httpStatus: 200 };
}

export interface DeviceVerifyStateInput {
	nowMs: number;
	expiresAtIso: string;
	authorizedAt: string | null;
	pilotApproved: boolean;
}

export type DeviceVerifyState =
	| { status: "expired"; httpStatus: 400; error: "device_code_expired" }
	| { status: "forbidden"; httpStatus: 403; error: "pilot_not_approved" }
	| { status: "already_authorized"; httpStatus: 409; error: "device_code_already_authorized" }
	| { status: "ok"; httpStatus: 200 };

export function evaluateDeviceVerifyState(input: DeviceVerifyStateInput): DeviceVerifyState {
	if (input.nowMs > Date.parse(input.expiresAtIso)) {
		return { status: "expired", httpStatus: 400, error: "device_code_expired" };
	}
	if (!input.pilotApproved) {
		return { status: "forbidden", httpStatus: 403, error: "pilot_not_approved" };
	}
	if (input.authorizedAt) {
		return { status: "already_authorized", httpStatus: 409, error: "device_code_already_authorized" };
	}
	return { status: "ok", httpStatus: 200 };
}
