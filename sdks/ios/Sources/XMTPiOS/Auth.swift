import Foundation
import LibXMTP

/// A credential used for gateway authentication.
public struct Credential {
	public var name: String?
	public var value: String
	public var expiresAtSeconds: Int64

	/// Convenience: expiry as a `Date`.
	public var expiresAt: Date {
		Date(timeIntervalSince1970: TimeInterval(expiresAtSeconds))
	}

	public init(name: String? = nil, value: String, expiresAtSeconds: Int64) {
		self.name = name
		self.value = value
		self.expiresAtSeconds = expiresAtSeconds
	}

	/// Convert from FFI representation.
	init(ffi: FfiCredential) {
		self.name = ffi.name
		self.value = ffi.value
		self.expiresAtSeconds = ffi.expiresAtSeconds
	}

	/// Convert to FFI representation.
	var ffi: FfiCredential {
		FfiCredential(
			name: name,
			value: value,
			expiresAtSeconds: expiresAtSeconds
		)
	}
}

/// Callback invoked when gateway authentication is required.
/// Return a fresh `Credential` (e.g. a signed JWT).
public typealias AuthCallback = () async throws -> Credential

/// Bridges a Swift `AuthCallback` closure to the FFI `FfiAuthCallback` protocol.
class AuthCallbackBridge: FfiAuthCallback {
	private let callback: AuthCallback

	init(_ callback: @escaping AuthCallback) {
		self.callback = callback
	}

	func onAuthRequired() async throws -> FfiCredential {
		let credential = try await callback()
		return credential.ffi
	}
}

/// Creates an internal FFI auth callback from a Swift closure, or returns nil if the closure is nil.
func makeInternalAuthCallback(_ callback: AuthCallback?) -> (any FfiAuthCallback)? {
	guard let callback = callback else { return nil }
	return AuthCallbackBridge(callback)
}

/// A handle that allows setting credentials programmatically (e.g. from a token refresh flow).
public class AuthHandle {
	private let ffiHandle: FfiAuthHandle

	public init() {
		self.ffiHandle = FfiAuthHandle()
	}

	/// Provide a fresh credential to the SDK.
	public func set(_ credential: Credential) async throws {
		try await ffiHandle.set(credential: credential.ffi)
	}

	/// Internal: get the underlying FFI handle for passing to `connectToBackend`.
	var ffi: FfiAuthHandle {
		ffiHandle
	}
}
