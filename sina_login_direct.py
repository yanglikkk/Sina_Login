# 这种登陆方式是参考别的网友的，虽然效率很高，但我觉得普适性不强
import time
import base64
import rsa
import math
import random
import binascii
import requests
import re
from urllib.parse import quote_plus
from code_verification import code_verificate
from bs4 import BeautifulSoup


# 构造 Request headers
agent = 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0'
headers = {
    'User-Agent': agent,
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Requested-With': 'XMLHttpRequest',
}

session = requests.session()

# 访问 初始页面带上 cookie
index_url = "http://weibo.com/login.php"
yundama_username = ''
yundama_password = ''
verify_code_path = './pincode.png'


def get_pincode_url(pcid):
    size = 0
    url = "http://login.sina.com.cn/cgi/pin.php"
    pincode_url = '{}?r={}&s={}&p={}'.format(url, math.floor(random.random() * 100000000), size, pcid)
    return pincode_url


def get_img(url):
    resp = requests.get(url, headers=headers, stream=True)
    with open(verify_code_path, 'wb') as f:
        for chunk in resp.iter_content(1000):
            f.write(chunk)


def get_su(username):
    """
    对 email 地址和手机号码 先 javascript 中 encodeURIComponent
    对应 Python 3 中的是 urllib.parse.quote_plus
    然后在 base64 加密后decode
    """
    username_quote = quote_plus(username)
    username_base64 = base64.b64encode(username_quote.encode("utf-8"))
    return username_base64.decode("utf-8")


# 预登陆获得 servertime, nonce, pubkey, rsakv
def get_server_data(su):
    pre_url = "http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su="
    pre_url = pre_url + su + "&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.18)&_="
    prelogin_url = pre_url + str(int(time.time() * 1000))
    pre_data_res = session.get(prelogin_url, headers=headers)

    sever_data = eval(pre_data_res.content.decode("utf-8").replace("sinaSSOController.preloginCallBack", ''))

    return sever_data


# 这一段用户加密密码，需要参考加密文件
def get_password(password, servertime, nonce, pubkey):
    rsaPublickey = int(pubkey, 16)
    key = rsa.PublicKey(rsaPublickey, 65537)  # 创建公钥,
    message = str(servertime) + '\t' + str(nonce) + '\n' + str(password)  # 拼接明文js加密文件中得到
    message = message.encode("utf-8")
    passwd = rsa.encrypt(message, key)  # 加密
    passwd = binascii.b2a_hex(passwd)  # 将加密信息转换为16进制。
    return passwd


def login(username, password):
    # su 是加密后的用户名
    su = get_su(username)
    sever_data = get_server_data(su)
    servertime = sever_data["servertime"]
    nonce = sever_data['nonce']
    rsakv = sever_data["rsakv"]
    pubkey = sever_data["pubkey"]
    password_secret = get_password(password, servertime, nonce, pubkey)

    postdata = {
        'entry': 'weibo',
        'gateway': '1',
        'from': '',
        'savestate': '7',
        'useticket': '1',
        'pagerefer': "http://login.sina.com.cn/sso/logout.php?entry=miniblog&r=http%3A%2F%2Fweibo.com%2Flogout.php%3Fbackurl",
        'vsnf': '1',
        'su': su,
        'service': 'miniblog',
        'servertime': servertime,
        'nonce': nonce,
        'pwencode': 'rsa2',
        'rsakv': rsakv,
        'sp': password_secret,
        'sr': '1366*768',
        'encoding': 'UTF-8',
        'prelt': '115',
        'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
        'returntype': 'META'
        }



    need_pin = sever_data['showpin']
    if need_pin == 1:
        # 你也可以改为手动填写验证码
        if not yundama_username:
            raise Exception('由于本次登录需要验证码，请配置顶部位置云打码的用户名{}和及相关密码'.format(yundama_username))
        pcid = sever_data['pcid']
        postdata['pcid'] = pcid
        img_url = get_pincode_url(pcid)
        get_img(img_url)
        verify_code = code_verificate(yundama_username, yundama_password, verify_code_path)
        postdata['door'] = verify_code

    login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)'
    login_page = session.post(login_url, data=postdata, headers=headers)
    cookies = requests.utils.dict_from_cookiejar(session.cookies)
    login_loop = (login_page.content.decode("GBK"))
    pa = r'location\.replace\([\'"](.*?)[\'"]\)'
    loop_url = re.findall(pa, login_loop)[0]
    login_index = session.get(loop_url, headers=headers)
    cookies.update(requests.utils.dict_from_cookiejar(session.cookies))
    uuid = login_index.text
    uuid_pa = r'"uniqueid":"(.*?)"'
    uuid_res = re.findall(uuid_pa, uuid, re.S)[0]
    web_weibo_url = "http://weibo.com/%s/profile?topnav=1&wvr=6&is_all=1" % uuid_res
    weibo_page = session.get(web_weibo_url, headers=headers)
    cookies.update(requests.utils.dict_from_cookiejar(session.cookies))
    weibo_pa = r'<title>(.*?)</title>'
    user_name = re.findall(weibo_pa, weibo_page.content.decode("utf-8", 'ignore'), re.S)[0]
    # print(weibo_page.content.decode("utf-8", 'ignore'))
    # print("\n")
    home = r'bpfilter="main" href="(.*?)"'
    home_url = re.findall(home,weibo_page.text.replace('\\',""),re.S)[0]
    # print(weibo_page.content.decode("utf-8", 'ignore').replace('\\',""))
    time.sleep(2)
    response = session.get('http:'+home_url, headers=headers)
    cookies.update(requests.utils.dict_from_cookiejar(session.cookies))
    # print(response.text)
    oo = r'action-type="fl_like"  action-data="(.*?)"'
    # print(response.text.replace('\\',""))
    qq = r'div     mrid="(.*?)"'
    pp = re.findall(oo,response.text.replace('\\',""),re.S)[0]
    ww = re.findall(qq,response.text.replace('\\',""),re.S)[0]
    # print(response.text.replace('\\',""))
    print(pp)
    print(ww)
    data2 = []
    data1 = str(pp).split('&')
    print(data1)
    for i in data1:
        data2.append(i.split('=')[1])
    print(data2)
    rid = str(ww).split('=')[1]
    print(rid)
    good_data = {
        'location': 'v6_content_home',
        'group_source': 'group_all',
        'rid': rid,
        # 'mark': '1_C83DE66500736F767232F1391AD2BFF5FF3849871B77BA9AFA28D89552F4025FDCA4A884959E23471E332126AA5D260115B8585BEC71272FB900D432FD11635E4B8664B0FB46CDE6937E1AD6543E779D1BDACE1608A6350D567A591D15348930D8E52220A3D4CE0C46DCDEA17EF6DE8F',
        'version': data2[0],
        'qid': data2[1],
        'mid': data2[2],
        'like_src': data2[3],
        # 'cuslike': 1,
        # 'floating': 0,
        # 'monitor_mask': 0,
        # '_t': 0,
        # 'ajwvr':'6',
    }
    now_time = str(int(time.time() * 1000))
    good_data.update({'__rnd':now_time})
    url = 'https://weibo.com/aj/v6/like/add?ajwvr=6'
    headers.update({'Host': 'weibo.com'})
    headers.update({'Origin':'http://weibo.com'})
    headers.update({'Referer':'http:'+home_url})
    # result = requests.post(url= url ,cookies = cookies,headers = headers,data = good_data)
    # result = session.post(url, data=good_data, headers=headers,cookies = cookies)
    # print(url)
    # print(good_data)
    # print(cookies)
    # print(result.text)
    # print('登陆成功，你的用户名为：'+user_name)
    print(home_url)
    domain = str(home_url).split('/')[4]
    print(domain)
    # time_now = time.ctime()
    # send_data = {
    #     'location': 'v6_content_home',
    #     'rank': 0,
    #     'style_type': 1,
    #     # 'mark': '1_C83DE66500736F767232F1391AD2BFF5FF3849871B77BA9AFA28D89552F4025FDCA4A884959E23471E332126AA5D260115B8585BEC71272FB900D432FD11635E4B8664B0FB46CDE6937E1AD6543E779D1BDACE1608A6350D567A591D15348930D8E52220A3D4CE0C46DCDEA17EF6DE8F',
    #     'isReEdit': 'false',
    #     'module': 'stissue',
    #     'pub_source': 'main_',
    #     'pub_type': 'dialog',
    #     'isPri': 0,
    #     '_t': 0,
    #     'text':str(time_now)+'[doge][污]'
    # }
    # send_url = 'https://weibo.com/aj/mblog/add?ajwvr=6'
    headers.update({'referer':'http:'+home_url+'?wvr=5'})
    # send_result = requests.post(url= send_url ,cookies = cookies,headers = headers,data = send_data)
    # print(send_result.text)
    #transmit---------------------------------------------------------------------------------------------
    # time2 = time.time()*1000
    # transmit_data = {
    #     'location': 'v6_content_home',
    #     'rank': 0,
    #     'style_type': 1,
    #     # 'mark': '1_C83DE66500736F767232F1391AD2BFF5FF3849871B77BA9AFA28D89552F4025FDCA4A884959E23471E332126AA5D260115B8585BEC71272FB900D432FD11635E4B8664B0FB46CDE6937E1AD6543E779D1BDACE1608A6350D567A591D15348930D8E52220A3D4CE0C46DCDEA17EF6DE8F',
    #     'isReEdit': 'false',
    #     'module': 'stissue',
    #     'pub_source': 'main_',
    #     'pub_type': 'dialog',
    #     'isPri': 0,
    #     '_t': 0,
    #     'ajwvr':6,
    #     'domain':domain,
    #     '__rnd':time2,
    #     'mid': data2[2],
    #     'reason':'转发微博',
    #     'from_plugin':0,
    #     'group_source': 'group_all',
    #     'rid': rid,
    #     'isReEdit':'false'
    # }
    # transmit_url = 'https://weibo.com/aj/v6/mblog/forward?ajwvr=6'
    # transmit_result = requests.post(url=transmit_url, cookies=cookies, headers=headers, data=transmit_data)
    # print(transmit_result.text)
    headers.update({'referer':'http:'+home_url})
    save_data = {
        'location': 'v6_content_home',
        'group_source': 'group_all',
        'rid': rid,
        # 'mark': '1_C83DE66500736F767232F1391AD2BFF5FF3849871B77BA9AFA28D89552F4025FDCA4A884959E23471E332126AA5D260115B8585BEC71272FB900D432FD11635E4B8664B0FB46CDE6937E1AD6543E779D1BDACE1608A6350D567A591D15348930D8E52220A3D4CE0C46DCDEA17EF6DE8F',
        'version': data2[0],
        'qid': data2[1],
        'mid': data2[2],
        'like_src': data2[3],
        # 'cuslike': 1,
        # 'floating': 0,
        # 'monitor_mask': 0,
        # '_t': 0,
        # 'ajwvr':'6',
    }
    save_url = 'https://weibo.com/aj/fav/mblog/add?ajwvr=6'
    save_result = requests.post(url=save_url, cookies=cookies, headers=headers, data=save_data)
    print(save_result.text)
if __name__ == "__main__":
    username = 'xxxxx@qq.com'
    password = 'xxxxx'
    login(username, password)