;;;; Copyright © Paul Stadig. All rights reserved.
;;;;
;;;; This Source Code Form is subject to the terms of the Mozilla Public
;;;; License, v. 2.0. If a copy of the MPL was not distributed with this file,
;;;; You can obtain one at http://mozilla.org/MPL/2.0/.
;;;;
;;;; This Source Code Form is "Incompatible With Secondary Licenses", as defined
;;;; by the Mozilla Public License, v. 2.0.
(ns alice.core-test
  (:require [alice.core :refer :all]
            [clojure.test :refer :all])
  (:import (java.nio ByteBuffer)))

(deftest test-digest
  (is (= "8d777f385d3dfec8815d20f7496026dc"
         (hexstr (digest "data" "MD5" {}))))
  (is (= "8d777f385d3dfec8815d20f7496026dc"
         (-> (ByteBuffer/wrap (.getBytes "data" "UTF-8"))
             (digest "MD5" {})
             hexstr))))

(deftest test-md5
  (is (= "8d777f385d3dfec8815d20f7496026dc"
         (hexstr (md5 "data")))))

(deftest test-sha256
  (is (= "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"
         (hexstr (sha256 "data")))))
