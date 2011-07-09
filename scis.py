#!/usr/bin/python -u
import silc

import os
import pwd
import socket
import time
import threading

class SupySilcClient(silc.SilcClient):
    servername = ""
    nickname = ""
    username = ""
    remoteport = 0

    def _to_hex(self, string):
        return u''.join(hex(ord(c)).replace('0x', '').zfill(2) for c in string)

    def __init__(self):
        keybase = '/tmp/silckey'
        pubkey = keybase + '.pub'
        privkey = keybase + '.prv'
        self.keys = None
        if os.path.exists(pubkey) and os.path.exists(privkey):
            self.keys = silc.load_key_pair(pubkey, privkey)
        else:
            self.keys = silc.create_key_pair(pubkey, privkey)


        self.isconnected = False
        self.users = {}    # use this to lookup nick to SilcUser objects
        self.channels = {} # use this to lookup channels to SilcChannel objects

    def start(self):
        silc.SilcClient.__init__(self, keys = self.keys, nickname=self.nickname, username=self.username)
      
    def get_nickmask(self, user):
         return self.users[user.fingerprint][0]

    def _cache_user(self, user):
        mask = user.nickname;
        i=0
        for fp in self.users:
            if fp!=user.fingerprint:
                if self.users[fp][0]==mask:
                    mask="%s_%d" % (user.nickname, i)
                    i+=1
        self.users[user.fingerprint] = [mask,user]

    def _cache_channel(self, channel):
        self.channels[channel.channel_name] = channel

    def running(self):
        print 'SILC: Running.'
        self.connect_to_server(self.servername, self.remoteport)

    def connected(self):
        print ':scis 001 %s :Connected to server.' % self.nickname
        self.isconnected = True

    def disconnected(self, msg):
        print 'ERROR :Disconnected from server.'
        self.isconnected = False
        sys.exit()

    def failure(self):
        print "SILC: Connection failure"
        self.isconnected = False

    #def command(self, success, code, command, status):
    #    print 'SILC: Command:', success, code, command, status

    def say(self, msg):
        pass

    def channel_message(self, sender, channel, flags, msg):
        print ':%s!%s@%s PRIVMSG %s :%s' % (self.get_nickmask(sender), sender.username, sender.hostname, channel, msg)
        self._cache_channel(channel)
        self._cache_user(sender)

    def private_message(self, sender, flags, msg):
        print 'SILC: Private Message: [%s] %s' % (sender, msg)
        self._cache_user(sender)
        self.send_private_message(sender, 'Wow, I never knew %s' % msg)

    def notify_none(self, msg):
        print ':scis NOTICE %s :%s' % (thread.c.nickname, msg)

    def notify_join(self, joiner, channel):
        self._cache_user(joiner)
        print ':%s!%s JOIN :%s' % (self.get_nickmask(joiner), joiner.hostname, channel)
        thread.c.command_call("USERS %s" % channel)

    def notify_invite(self, channel, channel_name, inviter):
        print 'SILC: Notify (Invite):', channel, channel_name, inviter

    def notify_leave(self, leaver, channel):
        self._cache_user(leaver)
        self._cache_channel(channel)
        print ':%s!%s PART %s' % (self.get_nickmask(leaver), leaver.hostname, channel)

    def notify_signoff(self, user, msg, channel):
        self._cache_user(user)
        print ':%s!%s QUIT' % ( self.get_nickmask(user), user.hostname)

    def notify_topic_set(self, type, changedby, channel, topic):
        self._cache_user(changedby)
        self._cache_channel(channel)
        print 'SILC: Notify (Topic Set):', channel, topic

    def notify_nick_change(self, user, olduser, newuser):
        oldnick=self.get_nickmask(user)
        self._cache_user(user)
        print ':%s NICK %s' % (oldnick,self.get_nickmask(user))

    def notify_cmode_change(self, *args):
        pass # TODO: not implemented

    def notify_cumode_change(self, *args):
        pass # TODO: not implemented

    def notify_motd(self, msg):
        for line in msg.split('\n'):
            print ":scis 372 %s :%s" % (thread.c.nickname, line)
        print ":scis 376 %s :End of /MOTD command." % thread.c.nickname

    def notify_server_signoff(self):
        print 'SILC: Notify (Server Signoff)'

    def notify_kicked(self, kicked, reason, kicker, channel):
        self._cache_user(kicked)
        self._cache_user(kicker)
        self._cache_channel(channel)
        print 'SILC: Notify (Kick):', kicked, reason, kicker, channel

    def notify_killed(self, *args):
        pass # TODO: not implemented

    def notify_error(self, type, message):
        print 'SILC: Notify (Error):', type, message

    def notify_watch(self, watched, new_nick, new_user_mode, notification, _):
        self._cache_user(watched)
        print 'SILC: Notify (Watch):', watched

    def command_reply_whois(self, user, nickname, username, realname, mode, idle):
        self._cache_user(user)
        print 'SILC: Reply (Whois): %s mode: %x idle: %d' % (nickname, mode, idle)

    def command_reply_whowas(self, user, nickname, username, realname):
        self._cache_user(user)
        print 'SILC: Reply (Whowas):', nickname

    def command_reply_nick(self, user, nickname, olduserid):
        self._cache_user(user)

    def command_reply_list(self, channel, channel_name, channel_topic, user_count):
        if channel == None:
            print 'SILC: Reply (List): END'
        else:
            self._cache_channel(channel)
            print 'SILC: Reply (List):', channel_name, channel_topic

    def command_reply_topic(self, channel, topic):
        self.cache_channel(channel)
        print 'SILC: Reply (Topic):', channel, topic

    def command_reply_invite(self, *args):
        pass # TODO: not implemented

    def command_reply_kill(self, user):
        self._cache_user(user)
        print 'SILC: Reply (Kill):', user

    def command_reply_info(self, *args):
        pass # TODO: not implemented

    def command_reply_stats(self, *args):
        pass # TODO: not implemented

    def command_reply_ping(self):
        print 'PONG :scis'

    def command_reply_oper(self):
        print 'SILC: Reply (Oper)'

    def command_reply_join(self, channel, channel_name, topic, hmac_name, mode, user_limit, users):
        self._cache_channel(channel)

    def command_reply_motd(self, msg):
        print 'SILC: Reply (MOTD):', msg

    def command_reply_cmode(self, channel, mode, user_limit, founder_key, _):
        self._cache_channel(channel)
        print 'SILC: Reply (Cmode):', channel, mode

    def command_reply_cumode(self, mode, channel, user):
        self._cache_channel(channel)
        self._cache_user(user)
        print 'SILC: Reply (CUmode):', channel, user, mode

    def command_reply_kick(self, channel, user):
        self._cache_channel(channel)
        self._cache_user(user)
        print 'SILC: Reply (Kick):', channel, user

    def command_reply_ban(self, channel, banlist):
        self._cache_channel(channel)
        print 'SILC: Reply (Ban):', channel

    def command_reply_detach(self):
        print 'SILC: Reply (Detach)'

    def command_reply_watch(self):
        print 'SILC: Reply (Watch)'

    def command_reply_silcoper(self):
        print 'SILC: Reply (SilcOper)'

    def command_reply_leave(self, channel):
        self._cache_channel(channel)
        print 'SILC: Reply (Leave):', channel

    def command_reply_users(self, channel, users):
        
        for user in users:
            self._cache_user(user)
            server=user.server
            if not server:
                server="scis"
            print ":scis 352 %s %s %s %s %s %s H :0 %s" % (thread.c.nickname, channel, user.username, user.hostname, server, self.get_nickmask(user), user.nickname)
        print ":scis 315 %s %s :End of /WHO list." % (thread.c.nickname, channel)
        namesanswer=":scis 353 %s = %s :" % (thread.c.nickname, channel)
        for user in users:
            currnick=self.get_nickmask(user)
            if len(namesanswer)+len(currnick)<511:
                namesanswer+=" "+currnick
            else:
                print namesanswer
                namesanswer=":scis 353 %s = %s :" % (thread.c.nickname, channel)
        print namesanswer
        print ":scis 366 %s %s :End of /NAMES list." % (thread.c.nickname, channel)


    def command_reply_service(self, *args):
        pass # not implemented

    def command_reply_failed(self, command, commandstr, errorcode, errormsg):
        # global catching failed commands and their error codes
        print 'SILC: Reply (FAILED)!', commandstr, errormsg
    
class SILCThread(threading.Thread):
    c = SupySilcClient()
    run=True
    def __init__(self):
        threading.Thread.__init__(self) 
    def run(self):
        self.c.start()
        try:
            while self.run:
                self.c.run_one()
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass

def privmsg(linea,line):
    if linea[1] in thread.c.channels:
        if ':'==linea[2][0]:
            linea[2]=linea[2][1:]
        thread.c.send_channel_message(thread.c.channels[linea[1]], " ".join(linea[2:]))
    #thread.c.command_call(line.strip())

def try_to_connect():
    if thread.c.servername and thread.c.username and thread.c.nickname:
        thread.start()
    elif thread.c.username and thread.c.nickname:
        print ":scis 001 %s :Yo are %s, now tell me the SERVER" % (thread.c.nickname,thread.c.nickname)

def set_server(linea,line):
    if "" != thread.c.servername:
        return
    thread.c.servername=linea[1]
    if len(linea) > 2:
        try:
            thread.c.remoteport=int(linea[2])
        except:
            thread.c.remoteport=706
    else:
        thread.c.remoteport=706
    try_to_connect()

def set_nick(linea,line):
    thread.c.nickname=linea[1]
    try_to_connect()

def set_user(linea,line):
    thread.c.username=line.split(":")[1];
    try_to_connect()

def quit(linea,line):
    thread.run=False
    if thread.is_alive():
        thread.join()
    sys.exit()

def ignore_cmd(linea,line):
    pass

def jomat(linea,line):
    print "jomat!"+(" ".join(linea[1:]))
    thread.c.command_call(" ".join(linea[1:]))

commands = {"PRIVMSG":privmsg,
    "SERVER":set_server,
    "NICK":set_nick,
    "USER":set_user,
    "QUIT":quit,
    "MODE":ignore_cmd, # irssi wants to set the mode, just ignore it <- TODO
    "JOMAT":jomat
}


if __name__ == "__main__":
    import sys
    thread = SILCThread()
    print ":scis NOTICE AUTH :Hi there..."
    while True:
        line = sys.stdin.readline()
        if line=="":
            thread.run=False
            if thread.is_alive():
                thread.join()
            break # EOF
        if line == "\n":
            continue
        line=line.strip()
        linea=line.split(' ')
        command=linea[0].upper()
        if command in commands:
            commands[command](linea,line)
        else:
            thread.c.command_call(line.strip())


