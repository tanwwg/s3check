import Foundation
import CryptoKit

struct S3Sig {
    var signature: String
    var auth: String
}

struct S3Signer {

    let accessId: String
    let secretKey: String
    let awsRegion: String  // e.g. us-east-1
    let serviceType = "s3" // e.g. s3
    let date: Date
    
    private let hmacShaTypeString = "AWS4-HMAC-SHA256"
//    private let awsRegion = "us-east-1"
//    private let serviceType = "execute-api"
    private let aws4Request = "aws4_request"
    
    private let iso8601Formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.calendar = Calendar(identifier: .iso8601)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd'T'HHmmssXXXXX"
        return formatter
    }()
    
    private func iso8601() -> (full: String, short: String) {
        let date = iso8601Formatter.string(from: date)
        let index = date.index(date.startIndex, offsetBy: 8)
        let shortDate = date.substring(to: index)
        return (full: date, short: shortDate)
    }
    
    func sign(request: URLRequest) -> S3Sig {
        let date = iso8601()
                
        let body = request.httpBody ?? Data()
        let url = request.url!
        
        var headers = request.allHTTPHeaderFields ?? [:]
        headers["Host"] = url.host(percentEncoded: false)!
        headers["X-Amz-Date"] = date.full

        let signedHeaders = headers.map{ $0.key.lowercased() }.sorted().joined(separator: ";")
        
        let bodysha256 = toSha256Hex(data: body)
        
        let charset = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "/-._~"))
        
        var query = url.query(percentEncoded: true) ?? ""
        if query.count > 0, !query.contains("=") {
            query = query + "="
        }
        
        var path = url.path.addingPercentEncoding(withAllowedCharacters: charset) ?? ""
        if path.count == 0 { path = "/" }
        
        let canonicalRequest = [
            request.httpMethod ?? "GET",
            path,
            query,
            headers.map{ $0.key.lowercased() + ":" + $0.value }.sorted().joined(separator: "\n"),
            "",
            signedHeaders,
            bodysha256
        ].joined(separator: "\n")
        print("CANONICAL REQUEST")
        print(canonicalRequest)
        print("END CANONICAL REQUEST")
        let canonicalRequestHash = toSha256Hex(data: Data(canonicalRequest.utf8))
        
        let credential = [date.short, awsRegion, serviceType, aws4Request].joined(separator: "/")
        
        let stringToSign = [
            hmacShaTypeString,
            date.full,
            credential,
            canonicalRequestHash
            ].joined(separator: "\n")
        
        print("STRING TO SIGN")
        print(stringToSign)
        print("END STRING TO SIGN")
        
        let signature = hmacStringToSign(stringToSign: stringToSign, secretSigningKey: secretKey, shortDateString: date.short)
        print("sig:\(signature)")
        
        let authorization = hmacShaTypeString + " Credential=" + accessId + "/" + credential + ",SignedHeaders=" + signedHeaders + ",Signature=" + signature
        
        return S3Sig(signature: signature, auth: authorization)
//        signedRequest.addValue(authorization, forHTTPHeaderField: "Authorization")
//
//        return signedRequest
    }
    
    private func hmac256(p1: Data, p2: Data) -> Data {
        let auth = HMAC<SHA256>.authenticationCode(for: p2, using: SymmetricKey(data: p1))
        let data = auth.withUnsafeBytes { buffer in
            Data(bytes: buffer.baseAddress!, count: buffer.count)
        }
        return data
    }
    
    private func hmac256(p1: Data, s2: String) -> Data {
        return hmac256(p1: p1, p2: Data(s2.utf8))
    }
    
    private func toSha256Hex(data: Data) -> String {
        var sha256 = SHA256()
        sha256.update(data: data)
        let digest = sha256.finalize()
        return digest.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    private func hmacStringToSign(stringToSign: String, secretSigningKey: String, shortDateString: String) -> String {
        let k1 = "AWS4" + secretSigningKey
        let sk1 = hmac256(p1: Data(k1.utf8), s2: shortDateString)
        let sk2 = hmac256(p1: sk1, s2: awsRegion)
        let sk3 = hmac256(p1: sk2, s2: serviceType)
        let sk4 = hmac256(p1: sk3, s2: aws4Request)
        let signature = hmac256(p1: sk4, s2: stringToSign)
        return signature.compactMap { String(format: "%02x", $0) }.joined()
//
//        guard let sk1 = try? HMAC(key: [UInt8](k1.utf8), variant: .sha256).authenticate([UInt8](shortDateString.utf8)),
//            let sk2 = try? HMAC(key: sk1, variant: .sha256).authenticate([UInt8](awsRegion.utf8)),
//            let sk3 = try? HMAC(key: sk2, variant: .sha256).authenticate([UInt8](serviceType.utf8)),
//            let sk4 = try? HMAC(key: sk3, variant: .sha256).authenticate([UInt8](aws4Request.utf8)),
//            let signature = try? HMAC(key: sk4, variant: .sha256).authenticate([UInt8](stringToSign.utf8)) else { return .none }
//        return signature.toHexString()
    }
    
}

// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
func check1() {

    var req = URLRequest(url: URL(string: "https://examplebucket.s3.amazonaws.com/test.txt")!)
    req.addValue("bytes=0-9", forHTTPHeaderField: "range")
    req.addValue("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", forHTTPHeaderField: "x-amz-content-sha256")
    let date = try! Date("2013-05-24T00:00:00Z", strategy: .iso8601)
    let signer = S3Signer(accessId: "AKIAIOSFODNN7EXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", awsRegion: "us-east-1", date: date)
    let sig = signer.sign(request: req)
    assert(sig.signature == "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
    assert(sig.auth == "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
}

func check2() {

    var req = URLRequest(url: URL(string: "https://examplebucket.s3.amazonaws.com/test$file.text")!)
    req.httpMethod = "PUT"
    req.addValue("Fri, 24 May 2013 00:00:00 GMT", forHTTPHeaderField: "Date")
    req.addValue("REDUCED_REDUNDANCY", forHTTPHeaderField: "x-amz-storage-class")
    req.addValue("44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072", forHTTPHeaderField: "x-amz-content-sha256")
    let body = "Welcome to Amazon S3."
    req.httpBody = Data(body.utf8)
    
    let date = try! Date("2013-05-24T00:00:00Z", strategy: .iso8601)
    let signer = S3Signer(accessId: "AKIAIOSFODNN7EXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", awsRegion: "us-east-1", date: date)
    let sig = signer.sign(request: req)
    assert(sig.signature == "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd")
    assert(sig.auth == "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd")
}

func check3() {

    var req = URLRequest(url: URL(string: "https://examplebucket.s3.amazonaws.com?lifecycle")!)
    req.addValue("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", forHTTPHeaderField: "x-amz-content-sha256")
    let date = try! Date("2013-05-24T00:00:00Z", strategy: .iso8601)
    let signer = S3Signer(accessId: "AKIAIOSFODNN7EXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", awsRegion: "us-east-1", date: date)
    let sig = signer.sign(request: req)
    assert(sig.signature == "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543")
    assert(sig.auth == "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543")
}

func check4() {

    var req = URLRequest(url: URL(string: "https://examplebucket.s3.amazonaws.com?max-keys=2&prefix=J")!)
    req.addValue("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", forHTTPHeaderField: "x-amz-content-sha256")
    let date = try! Date("2013-05-24T00:00:00Z", strategy: .iso8601)
    let signer = S3Signer(accessId: "AKIAIOSFODNN7EXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", awsRegion: "us-east-1", date: date)
    let sig = signer.sign(request: req)
    assert(sig.signature == "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")
    assert(sig.auth == "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")
}

check1()
check2()
check3()
check4()

