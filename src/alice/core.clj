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
            [nio.core :as nio])
  (:import (java.io File)
           (java.nio ByteBuffer)
           (java.security MessageDigest)))

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
