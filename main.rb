# domain analysis 
# small projects for day 4 in ruby 
require 'socket'
require 'open-uri'
require 'net/http'
require 'whois'
require 'whois-parser'
require 'net/ssh'
require 'httparty'
require 'uri'
require 'openssl'
require 'net/dns'
require 'socket'
require 'net/http'
require 'colorize'
require 'tty-spinner'
require 'optparse'
require 'httparty'
require 'timeout'
require 'uri'




def sep(seperation)
    puts "#{seperation}"
end

def banner(color, filename)
    file = File.open(filename)
    fd = file.readlines.map(&:chomp)
    puts color, fd
    file.close
end

def info(domain, url)
    n = `host #{domain}`.match(/(\d{1,3}\.){3}\d{1,3}/).to_s
    URI.parse("#{url}").port 
    uri = URI.parse("#{url}")
    whois = Whois::Client.new
    whois.lookup("#{domain}")
    record = Whois.whois("#{domain}")
    parser = record.parser
    register = parser.registered?
    created = parser.created_on 
    main = parser.technical_contacts.first
    resolver = Net::DNS::Resolver.start("#{domain}")
    resol2 = Net::DNS::Resolver.start("#{domain}").answer
    resol3 = Net::DNS::Resolver.start("#{domain}", Net::DNS::MX).answer
    sep("\n\n")
    puts resolver
    sep("\n\n")
    puts resol2
    sep("\n\n")
    puts resol3
    puts "\033[31m[~] Name-Servers [~]"
    parser.nameservers.each do |nameserver|
        puts "\033[34m[+] -> #{nameserver}\033[34m"
    end
    sep("\n\n\n")
    uri = URI.parse("#{url}")
    http = Net::HTTP.new(uri.host, uri.port)
    userag     = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.54 Safari/537.36"
    uri  = URI.parse("#{url}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl        = true if uri.scheme == 'https'
    http.verify_mode    = OpenSSL::SSL::VERIFY_NONE
    date = Time.new 
    req  = Net::HTTP::Get.new(uri.request_uri)
    pp req.to_hash
    req["User-Agent"] = "#{userag}"
    res   = http.request(req)
    resur = Net::HTTP.get_response(URI.parse(url.to_s))
    res.code
    res.message 
    res.code_type
    res.content_type
    pp res.to_hash
    puts '-------------------------'
    puts '[*] Response ~> '  + resur.code 
    sleep 0.1
    puts '[*] Checking More Connections..'
    puts '--------------------------'
    a = HTTParty.get(url).headers
    ip = IPAddr.new(n)
    map = ip.ipv4_compat.to_string
    puts '[*] Query          => '  , uri.query  
    puts '[*] Scheme         => '  , uri.scheme
    puts '[*] Port  Main     => '  , uri.port
    puts '[*] HOSTNAME       => '  , uri.host
    puts '[*] Path           => '  , uri.path
    puts '[*] Request URI    => '  , uri.request_uri 
    puts '[*] Server         => '  +  a["server"] 
    puts '[*] Date           => '  +  a["date"] 
    puts '[*] Content        => '  +  a["content-type"] 
    puts '[*] Response Code  => '  + resur.code
    puts '[*] Last-mod       => '  
    puts a["last-modified"]
    puts '[*] trans-enc      => '  
    puts a["transfer-encoding"]
    puts '[*] Connection     => '  + a["connection"]
    puts '[*] Access-control => '  
    puts a["access-control-allow-origin"]
    puts '[*] Cache-control  => '  
    puts resur.response["Cache-Control"]
    puts '-----------------------SERVER INF--------------------'  
    puts '[*] Calculated IPV6 | '  + map                 
    puts '[*] Server IP       | '  + n 
    puts '[*] X-Frame-OP      | '  
    puts resur.response["x-frame-options"]
    puts '[*] X-XSS-Protect   | '  
    puts  resur.response["x-xss-protection"]
    puts '[*] X-Content-type  | '  
    puts resur.response["x-content-type-options"]
    puts '[*] Max-Age         |'  
    puts resur.response["max-age"]
    puts '[*] X-Request-ID    |' 
    puts resur.response["x-request-id"]
    puts '[*] X-Runtime       |' 
    puts resur.response["x-runtime"]
    puts '[*] Access Control  |' 
    puts resur.response["access_control_max_age"]
    puts '[*] Access Allow    |' 
    puts resur.response["access_control_allow_methods"]
    puts '[*] Content Length  |' 
    puts resur.response["content-length"]
    puts '[*] Connection      |' 
    puts resur.response["connection"]
    puts '[*] Content_Dispo   |' 
    puts resur.response["content_disposition"]
    puts '[*] Expires         |' 
    puts resur.response["expires"]
    puts '[*] set-cookie      |' 
    puts resur.response["set-cookie"]
    puts '[*] user-Agent      |' 
    puts resur.response["user-agent"]
    puts '[*] bfcache-opt-in  |' 
    puts resur.response["bfcache-opt-in"]
    puts '[*] Content encode  | ' 
    puts resur.response["content-encoding"]
    puts '[*] content-sec     | ' 
    puts resur.response["content-security-policy"]
    puts '[*] Session Cookie  |' 
    puts resur.response["set-cookie"]
    puts '[*] strict-trans    |' 
    puts resur.response["strict-transport-security"]
    puts '[*] method          |' 
    puts resur.response["method"]
end

def main()
    print"\x1b[H\x1b[2J\x1b[3J"
    banner("\033[34m", "banner.txt")
    print "Domain name -> "
    dom = gets.chomp
    print "URL > "
    url = gets.chomp
    info("#{dom}", "#{url}")
end

main