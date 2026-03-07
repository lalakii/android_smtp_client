# Android SMTP Client

[![Maven Central](https://img.shields.io/maven-central/v/cn.lalaki/android_smtp_client.svg?label=Maven%20Central&logo=sonatype)](https://central.sonatype.com/artifact/cn.lalaki/android_smtp_client)
![License: MIT (shields.io)](https://img.shields.io/badge/License-MIT-2F9D66?logo=github)

SmtpClient is a lightweight, pure-Java SMTP client library for Android.It supports STARTTLS (port 587) and implicit TLS (port 465), AUTH LOGIN, UTF-8 subjects and HTML bodies (base64), priority levels, and a simple callback listener for success/error/log.Designed for minimal dependencies and easy integration into Android apps that need to send emails programmatically.

## Gradle

```gradle
implementation "cn.lalaki:android_smtp_client:3.0.2" // Android

implementation "cn.lalaki:java_smtp_client:3.0.2" // Java
```

## API

[View code](https://github.com/lalakii/android_smtp_client/blob/master/app/src/main/java/cn/lalaki/mail/ui/MainActivity.java#L114)
```java
// The code must be executed in a thread.
new Thread(() -> {
    SmtpClient client = new SmtpClient.Builder().config(host, mPort, tlsMode, certVerifyDisable, username, password).build();
    client.sendMail(new SmtpClient.EmailMessage(to, subject, body, SmtpClient.ContentType.TEXT_HTML, attachments, SmtpClient.Priority.Normal), new SmtpClient.IMailSentListener() {
        @Override
        public void onSuccess() {
            // need runOnUiThread
        }

        @Override
        public void onError(Exception e) {
            // need runOnUiThread
        }

        @Override
        public void onLog(String log) {
            // need runOnUiThread
        }
    });
}).start();
```

## Demo APK

[Download](https://github.com/lalakii/android_smtp_client/releases)

## LICENSE

[MIT](./LICENSE)
