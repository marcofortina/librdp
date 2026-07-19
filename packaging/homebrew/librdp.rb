# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

class Librdp < Formula
  desc "RDP client library"
  homepage "https://github.com/marcofortina/librdp"
  license "AGPL-3.0-or-later"
  head "https://github.com/marcofortina/librdp.git", branch: "master"

  depends_on "cmake" => :build
  depends_on "pkg-config" => :build
  depends_on "openssl@3"

  def install
    args = std_cmake_args + %w[
      -DLIBRDP_BUILD_TESTS=ON
      -DLIBRDP_BUILD_EXAMPLES=ON
      -DLIBRDP_BUILD_FUZZ=OFF
      -DLIBRDP_BUILD_ADMIN=ON
      -DLIBRDP_BUILD_SERVER=ON
      -DLIBRDP_BUILD_VIEWER=ON
      -DLIBRDP_BUILD_WORKSPACE=ON
      -DLIBRDP_WITH_FFMPEG_AVC=OFF
      -DLIBRDP_WITH_OPENH264_AVC=OFF
      -DLIBRDP_WITH_PCSC=OFF
      -DLIBRDP_WITH_LIBUSB=OFF
      -DLIBRDP_WITH_FIDO2=OFF
      -DLIBRDP_WITH_CBOR=OFF
      -DLIBRDP_WITH_CUPS=OFF
      -DLIBRDP_WITH_ACL=OFF
      -DLIBRDP_WITH_ATTR=OFF
      -DLIBRDP_WITH_ARCHIVE=OFF
    ]

    system "cmake", "-S", ".", "-B", "build", *args
    system "cmake", "--build", "build"
    system "ctest", "--test-dir", "build", "--output-on-failure"
    system "cmake", "--install", "build"
  end

  test do
    (testpath/"consumer.c").write <<~C
      #include <librdp/librdp.h>
      int main(void)
      {
          librdp_settings* settings = librdp_settings_new();
          if (!settings)
              return 1;
          librdp_settings_free(settings);
          return 0;
      }
    C
    system ENV.cc, "consumer.c", "-I#{include}", "-L#{lib}", "-llibrdp", "-o", "consumer"
    system "./consumer"
    system bin/"librdp-admin", "--help"
    system bin/"librdp-server", "--help"
    system bin/"librdp-viewer", "--help"
    system bin/"librdp-workspace", "--help"
  end
end
