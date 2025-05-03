package com.codejam.codex.authzen.utils;

import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Service;

@Service
public class EmailUtil {

    private static final Logger logger = LoggerFactory.getLogger(EmailUtil.class);
    private final JavaMailSender javaMailSender;

    @Value("${email.from}")
    private String fromEmail;

    public EmailUtil(JavaMailSender javaMailSender) {
        this.javaMailSender = javaMailSender;
    }
    /**
     * Sends a plain text email (e.g., password reset email).
     *
     * @param toEmail   The recipient email.
     * @param subject   The email subject.
     * @param body      The email body (can include placeholders like ${RESET_LINK}).
     * @param resetLink The reset link to be injected into body.
     * @return true if email is sent successfully, false otherwise.
     */
    public boolean sendPasswordResetEmail(String toEmail, String subject, String body, String resetLink) {
        String formattedBody = body + "\n\n" + resetLink;
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject(subject);
            message.setText(formattedBody);
            javaMailSender.send(message);
            logger.info("Password reset email sent successfully to {}", toEmail);
            return true;
        } catch (MailException e) {
            logger.error("Failed to send password reset email to {}: {}", toEmail, e.getMessage());
            return false; // Return false on failure
        }
    }


    /**
     * Sends an HTML email (can be used for richer formatted emails).
     *
     * @param toEmail   The recipient email.
     * @param subject   The email subject.
     * @param body      The HTML body (can include placeholders like ${RESET_LINK}).
     * @param resetLink The reset link to be injected into body.
     * @return true if email is sent successfully, false otherwise.
     */
    public boolean sendPasswordResetEmailHtml(String toEmail, String subject, String body, String resetLink) {
        String formattedBody = body.replace("${RESET_LINK}", resetLink);
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);
            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(formattedBody, true); // Set true for HTML content
            javaMailSender.send(mimeMessage);
            logger.info("HTML Password reset email sent successfully to {}", toEmail);
            return true;
        } catch (MailException | jakarta.mail.MessagingException e) {
            logger.error("Failed to send HTML password reset email to {}: {}", toEmail, e.getMessage());
            return false; // Return false on failure
        }
    }
}
