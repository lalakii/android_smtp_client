package cn.lalaki.mail.ui;

import android.os.Bundle;
import android.view.View;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import cn.lalaki.smtp.SmtpClient;
import cn.lalaki.smtp.test.R;
import xyz.xxin.fileselector.FileSelector;
import xyz.xxin.fileselector.beans.FileBean;
import xyz.xxin.fileselector.interfaces.OnResultCallbackListener;

/**
 * Created on yyyy-MM-dd
 *
 * <p>测试类
 *
 * @author lalaki (i@lalaki.cn)
 * @since android_smtp_client <a href="https://github.com/lalakii/android_smtp_client/">android smtp client</a>
 */
public class MainActivity extends AppCompatActivity implements View.OnClickListener, RadioGroup.OnCheckedChangeListener {
    private EditText mServer;
    private EditText mPort;
    private EditText mUsername;
    private EditText mPassword;
    private EditText mTo;
    private EditText mSubject;
    private EditText mContent;
    private TextView mLog;
    private TextView mAttachmentCount;
    private CheckBox mVerify;
    private SmtpClient.TlsMode mTlsMode = SmtpClient.TlsMode.STARTTLS;

    private final List<File> selectedFiles = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        mLog = findViewById(R.id.log);
        mServer = findViewById(R.id.server);
        mServer.setText(R.string.default_server);
        mPort = findViewById(R.id.port);
        mPort.setText(R.string.default_port_start_tls);
        mUsername = findViewById(R.id.username);
        mPassword = findViewById(R.id.password);
        mSubject = findViewById(R.id.subject);
        mContent = findViewById(R.id.content);
        mVerify = findViewById(R.id.cert_verify);
        mAttachmentCount = findViewById(R.id.attachment_count);
        mTo = findViewById(R.id.to);
        mTo.setText(R.string.default_to);
        findViewById(R.id.send).setOnClickListener(this);
        findViewById(R.id.add_attachment).setOnClickListener(this);
        RadioGroup radioGroup = findViewById(R.id.proto_radio);
        radioGroup.setOnCheckedChangeListener(this);
    }

    @Override
    public void onClick(View view) {
        if (view.getId() == R.id.add_attachment) {
            // add
            FileSelector.create(this)
                    .forResult(new OnResultCallbackListener() {
                        @Override
                        public void onResult(List<FileBean> result) {
                            selectedFiles.clear();
                            for (FileBean bean : result) {
                                selectedFiles.add(bean.getFile());
                            }
                            TextView attachmentCount = mAttachmentCount;
                            if (attachmentCount != null) {
                                attachmentCount.setText(String.format("已选择附件数量: %s个", result.size() + 1));
                            }
                        }

                        @Override
                        public void onCancel() {
                        }
                    });
        } else {
            mLog.setText("");
            String host = mServer.getText().toString();
            int port = 587;
            try {
                port = Integer.parseInt(mPort.getText().toString());
            } catch (Exception ignored) {
            }
            String to = mTo.getText().toString();
            String username = mUsername.getText().toString();
            String password = mPassword.getText().toString();
            String subject = mSubject.getText().toString();
            String body = mContent.getText().toString();
            int mPort = port;
            boolean certVerifyDisable = mVerify.isChecked();
            SmtpClient.TlsMode tlsMode = mTlsMode;
            List<File> attachments;
            if (!selectedFiles.isEmpty()) {
                attachments = new ArrayList<>(selectedFiles);
            } else {
                attachments = null; // No attachments / 无附件
            }
            new Thread(() -> {
                SmtpClient client = new SmtpClient.Builder().config(host, mPort, tlsMode, certVerifyDisable, username, password).build();
                client.sendMail(new SmtpClient.EmailMessage(to, subject, body, SmtpClient.ContentType.TEXT_HTML, attachments, SmtpClient.Priority.Normal), new SmtpClient.IMailSentListener() {
                    @Override
                    public void onSuccess() {
                        runOnUiThread(() -> Toast.makeText(MainActivity.this, "Success", Toast.LENGTH_SHORT).show());
                    }

                    @Override
                    public void onError(Exception e) {
                        runOnUiThread(() -> {
                            Toast.makeText(MainActivity.this, "Failed", Toast.LENGTH_SHORT).show();
                            TextView logView = mLog;
                            logView.append(e.toString() + "\r\n");
                        });
                    }

                    @Override
                    public void onLog(String log) {
                        TextView logView = mLog;
                        logView.post(() -> logView.append(log + "\r\n"));
                    }
                });
            }).start();
        }
    }

    @Override
    public void onCheckedChanged(@androidx.annotation.NonNull RadioGroup radioGroup, int id) {
        if (id == R.id.legacy_tls) {
            mTlsMode = SmtpClient.TlsMode.IMPLICIT_TLS;
            mPort.setText(R.string.default_port_tls);
        } else if (id == R.id.start_tls) {
            mTlsMode = SmtpClient.TlsMode.STARTTLS;
            mPort.setText(R.string.default_port_start_tls);
        }
    }
}