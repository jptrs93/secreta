import Foundation
import LocalAuthentication

final class AuthChallenge {
    private final class ResultBox: @unchecked Sendable {
        var value: Bool = false
    }

    func evaluate(prompt: String) -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            return false
        }
        let semaphore = DispatchSemaphore(value: 0)
        let resultQueue = DispatchQueue(label: "secreta.auth.challenge")
        let resultBox = ResultBox()
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: prompt) { result, _ in
            resultQueue.async {
                resultBox.value = result
                semaphore.signal()
            }
        }
        semaphore.wait()
        return resultQueue.sync { resultBox.value }
    }
}
