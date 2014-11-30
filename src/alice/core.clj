;;;; Copyright © Paul Stadig. All rights reserved.
;;;;
;;;; This Source Code Form is subject to the terms of the Mozilla Public
;;;; License, v. 2.0. If a copy of the MPL was not distributed with this file,
;;;; You can obtain one at http://mozilla.org/MPL/2.0/.
;;;;
;;;; This Source Code Form is "Incompatible With Secondary Licenses", as defined
;;;; by the Mozilla Public License, v. 2.0.
(ns alice.core
  (:require [clojure.java.io :as io]
            [clojure.stacktrace]
            [nio.core :as nio])
  (:import (java.io ByteArrayInputStream ByteArrayOutputStream File
                    FilterInputStream FilterOutputStream IOException
                    InputStream OutputStream SequenceInputStream)
           (java.nio ByteBuffer)
           (java.security Key MessageDigest SecureRandom)
           (javax.crypto Cipher CipherInputStream CipherOutputStream Mac)
           (javax.crypto.spec IvParameterSpec SecretKeySpec)))

(defprotocol Hexstr
  (hexstr [this]))

(extend-protocol Hexstr
  (Class/forName "[B")
  (hexstr [this]
    (let [this ^bytes this
          sb (StringBuilder.)]
      (areduce this i sb
               sb
               (.append sb (format "%02x" (aget this i))))
      (.toString sb)))
  ByteBuffer
  (hexstr [this]
    (let [sb (StringBuilder.)
          buf (.duplicate this)]
      (loop []
        (when (pos? (.remaining buf))
          (.append sb (format "%02x" (.get buf)))
          (recur)))
      (.toString sb))))

(defprotocol Digest
  (digest [this alg opts]))

(extend-protocol Digest
  (Class/forName "[B")
  (digest [this alg opts]
    (let [d (MessageDigest/getInstance alg)]
      (.digest d this)))
  String
  (digest [this alg opts]
    (digest (.getBytes this "UTF-8") alg opts))
  ByteBuffer
  (digest [this alg opts]
    (let [d (MessageDigest/getInstance alg)]
      (.update d (.duplicate this))
      (.digest d)))
  File
  (digest [this alg opts]
    (let [d (MessageDigest/getInstance alg)
          buf (ByteBuffer/allocate (:buffer-size opts 1024))]
      (with-open [in (nio/readable-channel this)]
        (loop [r (.read in buf)]
          (when (pos? r)
            (.update d ^ByteBuffer (.flip buf))
            (recur (.read in (.clear buf))))))
      (.digest d))))

(defn md5
  [obj & {:as opts}]
  (digest obj "MD5" opts))

(defn sha256
  [obj & {:as opts}]
  (digest obj "SHA-256" opts))

(defn random-bytes
  [length algorithm]
  (let [bytes (byte-array length)]
    (.nextBytes (SecureRandom/getInstance algorithm) bytes)
    bytes))

(defn sha1prng-random-bytes
  {:tag 'bytes}
  [length]
  (random-bytes length "SHA1PRNG"))

(defn aes-random-key
  [bits]
  (SecretKeySpec. (sha1prng-random-bytes (/ bits 8)) "AES"))

(defn aes-encrypting-output-stream
  {:tag java.io.OutputStream}
  ([^OutputStream out key]
     (let [iv (sha1prng-random-bytes 16)]
       (.write out iv)
       (aes-encrypting-output-stream out key iv)))
  ([^OutputStream out ^Key key ^bytes iv]
     (let [cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")]
       (.init cipher Cipher/ENCRYPT_MODE key (IvParameterSpec. iv))
       (CipherOutputStream. out cipher))))

(defn aes-encrypting-input-stream
  {:tag java.io.InputStream}
  ([^InputStream in key]
     (let [iv (sha1prng-random-bytes 16)]
       (SequenceInputStream.
        (ByteArrayInputStream. iv)
        (aes-encrypting-input-stream in key iv))))
  ([^InputStream in ^Key key ^bytes iv]
     (let [cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")]
       (.init cipher Cipher/ENCRYPT_MODE key (IvParameterSpec. iv))
       (CipherInputStream. in cipher))))

(defn aes-decrypting-input-stream
  {:tag java.io.InputStream}
  ([^InputStream in key]
     (let [iv (byte-array 16)]
       (.read in iv)
       (aes-decrypting-input-stream in key iv)))
  ([^InputStream in ^Key key ^bytes iv]
     (let [cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")]
       (.init cipher Cipher/DECRYPT_MODE key (IvParameterSpec. iv))
       (CipherInputStream. in cipher))))
