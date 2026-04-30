import Foundation
import Security

fileprivate let extraCATrustDelegate = ExtraCATrustDelegate()

fileprivate var urlSession: URLSession = {
  let config = URLSessionConfiguration.default

  // Harbor expects a CSRF token to be present if the HTTP client
  // carries a session cookie between its requests[1] and fails if
  // it was not present[2].
  //
  // To fix that, we disable the automatic cookies carry in URLSession.
  //
  // [1]: https://github.com/goharbor/harbor/blob/a4c577f9ec4f18396207a5e686433a6ba203d4ef/src/server/middleware/csrf/csrf.go#L78
  // [2]: https://github.com/cirruslabs/tart/issues/295
  config.httpShouldSetCookies = false

  return URLSession(configuration: config, delegate: extraCATrustDelegate, delegateQueue: nil)
}()

class Fetcher {
  // Shared session that honours TART_EXTRA_CA_CERTS. Use this instead of
  // URLSession.shared anywhere tart talks HTTPS, so a custom CA from the
  // env var applies uniformly (OCI registry, --dir archive downloads, etc).
  static var sharedURLSession: URLSession { urlSession }

  static func fetch(_ request: URLRequest, viaFile: Bool = false) async throws -> (AsyncThrowingStream<Data, Error>, HTTPURLResponse) {
    let task = urlSession.dataTask(with: request)

    let delegate = Delegate()
    task.delegate = delegate

    let stream = AsyncThrowingStream<Data, Error> { continuation in
      delegate.streamContinuation = continuation
    }

    let response = try await withCheckedThrowingContinuation { continuation in
      delegate.responseContinuation = continuation
      task.resume()
    }

    return (stream, response as! HTTPURLResponse)
  }
}

fileprivate class Delegate: NSObject, URLSessionDataDelegate {
  var responseContinuation: CheckedContinuation<URLResponse, Error>?
  var streamContinuation: AsyncThrowingStream<Data, Error>.Continuation?

  private var buffer: Data = Data()
  private let bufferFlushSize = 16 * 1024 * 1024

  func urlSession(
    _ session: URLSession,
    dataTask: URLSessionDataTask,
    didReceive response: URLResponse,
    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
  ) {
    // Soft-limit for the maximum buffer capacity
    let capacity = min(response.expectedContentLength, Int64(bufferFlushSize))

    // Pre-initialize buffer as we now know the capacity
    buffer = Data(capacity: Int(capacity))

    responseContinuation?.resume(returning: response)
    responseContinuation = nil
    completionHandler(.allow)
  }

  func urlSession(
    _ session: URLSession,
    dataTask: URLSessionDataTask,
    didReceive data: Data
  ) {
    buffer.append(data)

    if buffer.count >= bufferFlushSize {
      streamContinuation?.yield(buffer)
      buffer.removeAll(keepingCapacity: true)
    }
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didCompleteWithError error: Error?
  ) {
    if let error = error {
      responseContinuation?.resume(throwing: error)
      responseContinuation = nil

      streamContinuation?.finish(throwing: error)
      streamContinuation = nil
    } else {
      if !buffer.isEmpty {
        streamContinuation?.yield(buffer)
        buffer.removeAll(keepingCapacity: true)
      }

      streamContinuation?.finish()
      streamContinuation = nil
    }
  }
}

// TLS challenge handler that augments the system trust store with
// additional CA certificates loaded from the path(s) in the
// TART_EXTRA_CA_CERTS environment variable.
//
// The variable may be empty (default behaviour, system trust only),
// a single PEM/DER file, a directory containing such files, or a
// colon-separated list of either. All loaded certificates are added
// as anchors *in addition to* the system anchors, so connections to
// public servers continue to validate normally.
fileprivate class ExtraCATrustDelegate: NSObject, URLSessionDelegate {
  private let extraAnchors: [SecCertificate] = ExtraCATrustDelegate.loadExtraAnchors()

  func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let trust = challenge.protectionSpace.serverTrust,
          !extraAnchors.isEmpty else {
      completionHandler(.performDefaultHandling, nil)
      return
    }

    SecTrustSetAnchorCertificates(trust, extraAnchors as CFArray)
    // false => use system anchors *as well as* our custom ones
    SecTrustSetAnchorCertificatesOnly(trust, false)

    var error: CFError?
    if SecTrustEvaluateWithError(trust, &error) {
      completionHandler(.useCredential, URLCredential(trust: trust))
      return
    }

    // Strict evaluation failed. If the chain is rooted in one of our
    // explicitly opted-in extra anchors, override Apple-specific SSL
    // policy issues (e.g. "Certificate exceeds maximum temporal validity
    // period") via SecTrustSetExceptions. Equivalent to a user clicking
    // "trust" in a browser, but scoped to this exact cert chain.
    if ExtraCATrustDelegate.chainEndsInOurAnchor(trust, anchors: extraAnchors),
       let exceptions = SecTrustCopyExceptions(trust) {
      SecTrustSetExceptions(trust, exceptions)
      var err2: CFError?
      if SecTrustEvaluateWithError(trust, &err2) {
        completionHandler(.useCredential, URLCredential(trust: trust))
        return
      }
    }

    let host = challenge.protectionSpace.host
    let reason = error.map { String(describing: $0) } ?? "unknown"
    FileHandle.standardError.write(Data("tart: SecTrustEvaluate failed for \(host) with extra anchors: \(reason)\n".utf8))
    completionHandler(.performDefaultHandling, nil)
  }

  private static func chainEndsInOurAnchor(_ trust: SecTrust, anchors: [SecCertificate]) -> Bool {
    guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
          let top = chain.last else {
      return false
    }
    let topData = SecCertificateCopyData(top) as Data
    return anchors.contains { (SecCertificateCopyData($0) as Data) == topData }
  }

  private static func loadExtraAnchors() -> [SecCertificate] {
    guard let raw = ProcessInfo.processInfo.environment["TART_EXTRA_CA_CERTS"], !raw.isEmpty else {
      return []
    }

    let fm = FileManager.default
    var paths: [String] = []
    for entry in raw.split(separator: ":", omittingEmptySubsequences: true).map(String.init) {
      var isDir: ObjCBool = false
      guard fm.fileExists(atPath: entry, isDirectory: &isDir) else {
        FileHandle.standardError.write(Data("tart: TART_EXTRA_CA_CERTS path does not exist: \(entry)\n".utf8))
        continue
      }
      if isDir.boolValue {
        if let entries = try? fm.contentsOfDirectory(atPath: entry) {
          for name in entries where !name.hasPrefix(".") {
            paths.append((entry as NSString).appendingPathComponent(name))
          }
        }
      } else {
        paths.append(entry)
      }
    }

    var anchors: [SecCertificate] = []
    for p in paths {
      guard let data = try? Data(contentsOf: URL(fileURLWithPath: p)) else { continue }
      anchors.append(contentsOf: parseCertificates(data: data))
    }

    if anchors.isEmpty {
      FileHandle.standardError.write(Data("tart: TART_EXTRA_CA_CERTS yielded no usable certificates\n".utf8))
    }

    return anchors
  }

  private static func parseCertificates(data: Data) -> [SecCertificate] {
    // Try DER first
    if let cert = SecCertificateCreateWithData(nil, data as CFData) {
      return [cert]
    }

    // Fall back to PEM (possibly a bundle)
    guard let text = String(data: data, encoding: .utf8) else { return [] }
    let begin = "-----BEGIN CERTIFICATE-----"
    let end = "-----END CERTIFICATE-----"

    var certs: [SecCertificate] = []
    var cursor = text.startIndex
    while let beginRange = text.range(of: begin, range: cursor..<text.endIndex),
          let endRange = text.range(of: end, range: beginRange.upperBound..<text.endIndex) {
      let b64 = text[beginRange.upperBound..<endRange.lowerBound]
        .components(separatedBy: .whitespacesAndNewlines)
        .joined()
      if let der = Data(base64Encoded: b64),
         let cert = SecCertificateCreateWithData(nil, der as CFData) {
        certs.append(cert)
      }
      cursor = endRange.upperBound
    }
    return certs
  }
}
