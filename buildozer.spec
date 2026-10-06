[app]
title = Virus Detector
package.name = virusdetector
package.domain = org.example.virusdetector

source.dir = .
source.include_exts = py,png,jpg,kv,atlas,yar,json,txt

version = 0.1

requirements = python3,kivy,requests,certifi,pyjnius,android

orientation = portrait
fullscreen = 0

android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE

android.api = 33
android.minapi = 21
android.archs = arm64-v8a, armeabi-v7a

p4a.source_dir = /opt/p4a-stable

android.accept_sdk_license = True

[buildozer]
log_level = 2
warn_on_root = 0
