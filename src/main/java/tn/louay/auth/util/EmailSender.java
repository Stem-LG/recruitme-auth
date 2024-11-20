package tn.louay.auth.util;

public interface EmailSender {
    void sendEmail(String toEmail, String body);
}