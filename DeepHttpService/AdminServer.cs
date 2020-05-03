using DeepCore;
using DeepCore.Log;
using DeepCrystal.ORM;
using DeepCrystal.ORM.Generic;
using DeepCrystal.ORM.Query;
using DeepCrystal.RPC;
using DeepMMO.Data;
using DeepMMO.Server;
using DeepMMO.Server.Connect;
using DeepMMO.Server.Gate;
using DeepMMO.Server.SystemMessage;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using ThreeLives.Service.Admin.Data;
using TLProtocol.Data;
using TLProtocol.Protocol.Client;
using TLServer.Common;
using TLServer.Common.Data;
using TLServer.Common.Protocol;

namespace ThreeLives.Service.Admin
{
    public class StringRequest
    {
        public string token;
        public string content;
        public string stamp;
    }

    public class StringResponse
    {
        public bool state;
        public string reason;
    }

    public class CustomResponse
    {
        public bool state;
        public string reason;
        public Object ext = null;
    }


    public class AdminServer : IService
    {
        private static Random random = new Random();

        protected readonly Logger log;
        protected IRemoteNodeInfo[] realmNodes;
        protected bool isReady = false;
        private HttpServer http;
        private string api_key = null;

        private QueryMappingReference<TLRoleSnap> queryRoleSnap;
        TLRoleAccountDataWriter tlRoleDataWriter;
        //public static AdminServer Instance { get; private set; }
        //------------------------------------------------------------------------------------------
        //public override bool IsConcurrent => false;
        //------------------------------------------------------------------------------------------
        public AdminServer(ServiceStartInfo start) : base(start)
        {
            this.log = LoggerFactory.GetLogger(start.Address.ServiceName);
            this.http = new HttpServer(start.Config["HTTPListen"].ToString(), this, log);
            start.Config.TryGetValue("APIKey", out api_key);
            //Instance = this;
        }
        protected override void OnDisposed()
        {
        }
        protected override Task OnStartAsync()
        {
            this.queryRoleSnap = RPGServerPersistenceManager.Instance.GetQueryReference<TLRoleSnap>(RPGServerPersistenceManager.TYPE_ROLE_SNAP_DATA, this);

            tlRoleDataWriter = new TLRoleAccountDataWriter(this);
            return Execute(() =>
            {
                try
                {
                    this.http.Start();
                }
                catch (Exception e)
                {
                    log.Error(e);
                    http = null;
                }
            });
        }
        protected override Task OnStopAsync(ServiceStopInfo stop)
        {
            if (http != null)
                http.Dispose();

            //Instance = null;
            return Task.CompletedTask;
        }
        //------------------------------------------------------------------------------------------

        //[RpcHandler(typeof(SystemShutdownNotify))]
        //public virtual void rpc_HandleSystem(SystemShutdownNotify shutdown)
        //{
        //}

        public static string SHA1HashStringForUTF8String(string s)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(s);

            var sha1 = SHA1.Create();
            byte[] hashBytes = sha1.ComputeHash(bytes);

            return HexStringFromBytes(hashBytes);
        }

        public static string HexStringFromBytes(byte[] bytes)
        {
            var sb = new StringBuilder();
            foreach (byte b in bytes)
            {
                var hex = b.ToString("x2");
                sb.Append(hex);
            }
            return sb.ToString();
        }

        private bool VerifyStamp(string stamp)
        {
            int t = int.Parse(stamp);
            int unixTimestamp = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            //Console.WriteLine(unixTimestamp+ " "+stamp);
            return Math.Abs(t - unixTimestamp) < 100;
        }

        private bool VerifyContent(StringRequest sr, out string content)
        {
            sr.content = sr.content.Replace(" ", "%2B");
            var bytes = Convert.FromBase64String(Uri.UnescapeDataString(sr.content));
            content = System.Text.Encoding.UTF8.GetString(bytes);
            //log.Info(json + " " + api_key + " " + sr.stamp);
            string s = api_key + content + sr.stamp;
            var my = SHA1HashStringForUTF8String(s);
            //log.Info(my + " " + sr.token);
            return my == sr.token;
        }

        private string ResponseResult(bool state, string reason = null)
        {
            string defReason = state ? "success" : "unknow command";
            StringResponse sr = new StringResponse
            {
                state = state,
                reason = string.IsNullOrEmpty(reason) ? defReason : reason
            };
            return JsonConvert.SerializeObject(sr);
        }

        private string CustomResult(bool state, Object ext, string reason = null)
        {
            string defReason = state ? "success" : "unknow command";
            var obj = new CustomResponse
            {
                state = state,
                reason = string.IsNullOrEmpty(reason) ? defReason : reason,
                ext = JsonConvert.SerializeObject(ext)
            };
            return JsonConvert.SerializeObject(obj);
        }

        public async virtual Task<string> OnHandleHttpRequest(StringRequest msg)
        {
            log.Info("[Admin] " + msg.token);
            if (!VerifyStamp(msg.stamp))
            {
                throw new Exception("VerifyStamp failed");
            }

            if (!VerifyContent(msg, out string json))
            {
                throw new Exception("VerifyContent failed");
            }
            //TODO在这里分发处理不同的需求
            var jsonObj = JsonConvert.DeserializeObject(json) as JObject;

            switch (jsonObj["cmd"].ToString())
            {
                case CmdType.ServerMailType:
                    return await OnHandleServerMail(jsonObj);
                case CmdType.ServerAnnouncement:
                    return await OnHandleServerAnnouncement(jsonObj);
                case CmdType.ServerRoleBlacklist:
                    return await OnHandleServerBlacklist(jsonObj);
                case CmdType.ServerRoleBan:
                    return await OnHandleServerBan(jsonObj);
                case CmdType.ServerRoleToUUID:
                    return await OnHandleServerRoleNameToUUID(jsonObj);
                case CmdType.ServerRolePrivilege:
                    return await OnHandleServerRolePrivilege(jsonObj);
                case CmdType.ServerItemBase:
                    return OnHandleServerItemBase(jsonObj);
                case CmdType.ServerRoleBagQuery:
                    return await OnHandleServerRoleBagQuery(jsonObj);
                case CmdType.ServerRoleBagModify:
                    return await OnHandleServerRoleBagModify(jsonObj);
                case CmdType.ServerAccountQuery:
                    return await OnHandleServerAccountQuery(jsonObj);
                default:
                    break;
            }
            return ResponseResult(false);
        }

        /// <summary>
        /// 处理角色封停
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        private async Task<string> OnHandleServerBan(JObject obj)
        {
            var type = (BanType)obj["type"].ToObject<short>();
            var rolename_list = obj["role"].ToString().Split(',');
            var reason = obj["reason"].ToString();
            var final_date = DateTime.UtcNow;
            switch (type)
            {
                case BanType.Ban_Seven:
                    final_date = final_date.AddDays(7);
                    break;
                case BanType.Ban_Month:
                    final_date = final_date.AddMonths(1);
                    break;
                case BanType.Ban_Year:
                    final_date = final_date.AddYears(1);
                    break;
                case BanType.Ban_Forever:
                    final_date = final_date.AddYears(99);
                    break;
                case BanType.Ban_Cancel:
                    final_date.AddDays(-1);
                    break;
            }
            //TODO 接口不支持多用户暂时写死
            var roleDataWriter = new TLRoleDataStatusSnapWriter(this);
            string roleUUID = null;
            var result = await roleDataWriter.SuspendRoleData(rolename_list[0], final_date, reason, string.Empty);


            //KICK Logic.
            if (type != BanType.Ban_Cancel && !string.IsNullOrEmpty(result.Item3))
            {
                roleUUID = result.Item3;
                var logic = await this.Provider.GetAsync(ServerNames.GetLogicServiceAddress(roleUUID));
                if (logic != null && logic.Config.TryGetValue("sessionName", out var sessionName))
                {
                    var session = await this.Provider.GetAsync(new RemoteAddress(sessionName));
                    if (session != null)
                    {
                        var notify = new KickPlayerNotify();
                        notify.reason = reason;
                        session.Invoke(notify);
                    }
                }

            }

            if (result.Item1)
            {
                return ResponseResult(true);
            }
            else
            {
                return ResponseResult(false, result.Item2);
            }


        }

        /// <summary>
        /// 处理角色禁言
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        private async Task<string> OnHandleServerBlacklist(JObject obj)
        {
            var channel_arr = obj["channel"].ToObject<short[]>();

            var role_list = obj["role"].ToString().Split(',');

            if (channel_arr.Length > 0)
            {
                var type = (MuteType)obj["type"].ToObject<short>();
                var final_date = DateTime.UtcNow;
                switch (type)
                {
                    case MuteType.Mute_Hour:
                        final_date = final_date.AddHours(1);
                        break;
                    case MuteType.Mute_Month:
                        final_date = final_date.AddMonths(1);
                        break;
                    case MuteType.Mute_Year:
                        final_date = final_date.AddYears(1);
                        break;
                    case MuteType.Mute_Forever:
                        final_date = final_date.AddYears(99);
                        break;
                    case MuteType.Mute_Cancel:
                        final_date.AddDays(-1);
                        break;
                }
                //TODO 接口不支持多用户暂时写死
                var role_uuid = await RPGServerPersistenceManager.Instance.GetRoleUUIDByNameAsync(role_list[0], this);
                var result = await TLGMUtil.ForbidChat(this, role_uuid, final_date);
                return ResponseResult(result);
            }

            return ResponseResult(false);
        }

        /// <summary>
        /// GMT系统广播
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        private Task<string> OnHandleServerAnnouncement(JObject obj)
        {
            var channel_arr = obj["channel"].ToObject<List<short>>();

            if (channel_arr.Count > 0)
            {
                bool result = false;
                var primary_channel = channel_arr.Contains(ClientChatRequest.CHANNEL_SYSTEM) ? ClientChatRequest.CHANNEL_SYSTEM : ClientChatRequest.CHANNEL_TYPE_WORLD;
                List<string> groups = obj["group"].ToObject<List<string>>();
                TLClientChatNotify notify = new TLClientChatNotify();
                notify.channel_type = primary_channel;
                channel_arr.Remove(primary_channel);
                if (channel_arr.Count > 0)
                    notify.show_channel = channel_arr.ToArray();
                notify.func_type = obj["style"].ToObject<short>();
                notify.content = obj["text"].ToString();
                result = TLGMUtil.PushPublicMessage(this, (CHANNEL_TYPE)primary_channel, notify, groups);
                return Task.FromResult(ResponseResult(result));
            }

            return Task.FromResult(ResponseResult(false));
        }

        /// <summary>
        /// GMT邮件处理
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        private async Task<string> OnHandleServerMail(JObject obj)
        {
            if (int.TryParse(obj["type"].ToString(), out int userType))
            {
                var title = obj["mail"]["title"].ToString();
                var content = obj["mail"]["content"].ToString();

                JToken token = obj["mail"]["item"];
                var itemList = new List<TLProtocol.Data.ItemSnapData>();
                if (token != null)
                {
                    var item_list = JsonConvert.DeserializeObject<dynamic>(obj["mail"]["item"].ToString());
                    foreach (var item in item_list)
                    {
                        var id = item.id;
                        var count = item.num;
                        var itemData = new TLProtocol.Data.ItemSnapData
                        {
                            TemplateID = id,
                            Count = count
                        };
                        itemList.Add(itemData);
                    }
                }

                if (userType == (int)UserType.OnlineUser)
                {
                    return ResponseResult(true);
                }
                else if (userType == (int)UserType.AllUser)
                {
                    var groups = obj["group"].ToObject<string[]>();
                    foreach (var group in groups)
                    {
                        TLGlobalMailData mail = new TLGlobalMailData
                        {
                            title = title,
                            content = content,
                            groupId = group,
                            create_time = System.DateTime.UtcNow,
                            uuid = System.Guid.NewGuid().ToString(),
                            mail_type = TLMailData.TLMailType.Type_GM
                        };

                        if (itemList.Count > 0)
                        {
                            mail.attachments = itemList;
                        }

                        await new GlobalMailHandler(this).PostGlobalMailAsync(mail);
                    }
                    return ResponseResult(true);
                }
                else if (userType == (int)UserType.SpecificUser)
                {
                    var userList = obj["role_list"].ToString().Split(',');
                    var successUsers = new List<string>();
                    var wrongUsers = new List<string>();
                    var exceptionUsers = new List<string>();
                    var uuid_list = await GetManyUUID(userList);

                    var verifiedUsers = await RPGServerPersistenceManager.Instance.GetRoleNameByUUIDAsync(uuid_list, this);

                    for (int i = 0; i < verifiedUsers.Length; i++)
                    {
                        if (verifiedUsers[i].ToString() != null)
                        {
                            var notify = new TLSendGMMailNotify
                            {
                                roleId = uuid_list[i],
                                title = title,
                                content = content
                            };

                            if (itemList.Count > 0)
                            {
                                notify.attachment = itemList;
                            }

                            try
                            {
                                var cmd = new TLCmdPublisher(this.Provider, uuid_list[i]);
                                await cmd.PostCmdEvtAsync(notify);
                                successUsers.Add(userList[i]);
                            }
                            catch (Exception e)
                            {
                                e.FullStackTrace();
                                exceptionUsers.Add(userList[i]);
                            }

                        }
                        else
                        {
                            wrongUsers.Add(userList[i]);
                        }
                    }

                    if (successUsers.Count == userList.Length)
                    {
                        return ResponseResult(true);
                    }
                    else
                    {
                        var reason = new StringBuilder();
                        if (successUsers.Count > 0) reason.AppendFormat("成功用户({0}) : {1}", successUsers.Count, successUsers.ListToString(","));
                        if (wrongUsers.Count > 0) reason.AppendFormat("\n无效用户({0}) : {1}", wrongUsers.Count, wrongUsers.ListToString(","));
                        if (exceptionUsers.Count > 0) reason.AppendFormat("\n失败用户({0}) : {1}", exceptionUsers.Count, exceptionUsers.ListToString(","));
                        return ResponseResult(false, reason.ToString());
                    }
                }

                return ResponseResult(true);
            }
            return ResponseResult(false);
        }

        private async Task<string> OnHandleServerRoleNameToUUID(JObject obj)
        {
            var role_uuid = obj["role"].ToString();

            role_uuid = await GetRoleUUID(role_uuid);

            if (!string.IsNullOrEmpty(role_uuid))
            {
                //TODO 接口不支持多用户暂时写死
                if (role_uuid.Length < 36)
                {
                    role_uuid = await RPGServerPersistenceManager.Instance.GetRoleUUIDByNameAsync(role_uuid, this);
                }

                if (!string.IsNullOrEmpty(role_uuid))
                {
                    TLRoleSnap roleSnap = await this.queryRoleSnap.LoadDataAsync(role_uuid) as TLRoleSnap;
                    //var param_list = new Dictionary<string, object>();
                    //if (roleSnap.account_uuid.IndexOf(':') != -1)
                    //{
                    //    var new_account = roleSnap.account_uuid.Split(':');
                    //    param_list.Add("account_id", new_account[1]);
                    //}
                    //else
                    //{
                    //    param_list.Add("account_id", roleSnap.account_uuid);
                    //}
                    //param_list.Add("server_id", roleSnap.server_id);
                    //param_list.Add("role_uuid", role_uuid);
                    return CustomResult(true, roleSnap);
                }
            }

            return CustomResult(false, null, "role_name_not_exist");
        }

        private async Task<string> OnHandleServerRolePrivilege(JObject obj)
        {
            var roleName = obj["role"].ToString();
            if (!string.IsNullOrEmpty(roleName))
            {
                var privilege = obj.Value<int?>("privilege") ?? 0;
                RolePrivilege rolePrivilege = (RolePrivilege)privilege;
                string operatorId = obj["operator"].ToString();
                var result = await tlRoleDataWriter.SetRolePrivilege(roleName, rolePrivilege, operatorId);

                if (result.Item1)
                    return ResponseResult(true);
                else
                    return ResponseResult(false, result.Item2);
            }
            return ResponseResult(false, "role_name_not_exist");
        }

        private string OnHandleServerItemBase(JObject obj)
        {
            var language_type = obj["lang"].ToString();

            var items = TLServerTemplateManager.Instance.AllItemTemplates;

            var lang = TLServerTemplateManager.TLServerInstance.GetLanguage(language_type);

            var items_value_key = new Dictionary<string, object>();

            foreach (var item in items)
            {
                items_value_key.Add(item.ID.ToString(), lang.GetString(item.Item.name));
            }

            return CustomResult(true, items_value_key);
        }

        private async Task<string> OnHandleServerRoleBagQuery(JObject obj)
        {
            try
            {
                var role_uuid = obj["role"].ToString();

                var bag_type = obj["bagType"].ToString();

                role_uuid = await GetRoleUUID(role_uuid);

                if (!string.IsNullOrEmpty(role_uuid))
                {
                    var mapping = new BagStoreDataMapping(bag_type, role_uuid, this);
                    var BagStoreData = await mapping.LoadDataAsync();
                    return CustomResult(true, JsonConvert.SerializeObject(BagStoreData));
                }else
                {
                    return CustomResult(false, null, "role_name_not_exist");
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
                return CustomResult(false, null, "page_gmt_command_unknown_error");
            }

        }

        private async Task<string> OnHandleServerAccountQuery(JObject obj)
        {
            try
            {
                var account_id = obj["account_id"].ToString();
                if (!string.IsNullOrEmpty(account_id))
                {
                    //角色列表//
                    List<RoleIDSnap> roleList = new List<RoleIDSnap>();
                    using (var accountRoleSnapSave = new MappingReference<AccountRoleSnap>(RPGServerPersistenceManager.TYPE_ACCOUNT_ROLE_SNAP_DATA, account_id, this))
                    {
                        var accountRoleSnap = await accountRoleSnapSave.LoadOrCreateDataAsync(() => new AccountRoleSnap());
                        foreach (var item in accountRoleSnap.roleIDMap)
                        {
                            roleList.Add(item.Value);
                        }
                    }

                    return CustomResult(true, JsonConvert.SerializeObject(roleList));
                }
                else
                {
                    return CustomResult(false, null, "role_name_not_exist");
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
                return CustomResult(false, null, "page_gmt_command_unknown_error");
            }

        }


        private async Task<string> OnHandleServerRoleBagModify(JObject obj)
        {
            try
            {
                var role_uuid = obj["role"].ToString();

                var bag_type = obj["bagType"].ToString();

                var action = obj["action"].ToString();

                var entry_key = obj.Value<int?>("entryKey") ?? -1;

                var val = obj.Value<uint?>("value") ?? 0;

                role_uuid = await GetRoleUUID(role_uuid);

                if (!string.IsNullOrEmpty(role_uuid))
                {
                    TLRoleSnap roleSnap = await this.queryRoleSnap.LoadDataAsync(role_uuid) as TLRoleSnap;

                    if(roleSnap.onlineState == RoleState.STATE_ONLINE)
                    {
                        return CustomResult(false, null, "role_still_online");
                    }
                }

                if (!string.IsNullOrEmpty(role_uuid))
                {
                    var mapping = new BagStoreDataMapping(bag_type, role_uuid, this);
                    var BagStoreData = await mapping.LoadDataAsync();

                    if (BagStoreData != null && BagStoreData.Slots != null && BagStoreData.Slots.Count > 0)
                    {
                        if (BagStoreData.Slots.ContainsKey(entry_key))
                        {
                            if (action == "remove")
                            {
                                BagStoreData.Slots.Remove(entry_key);
                            }
                            else
                            {
                                BagStoreData.Slots[entry_key].Count = val;
                            }

                        }

                        await mapping.SaveDataAsync();

                        return CustomResult(true, null);
                    }

                    return CustomResult(false, null, "page_gmt_command_unknown_error");
                }
                else
                {
                    return CustomResult(false, null, "role_name_not_exist");
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
                return CustomResult(false, null, "page_gmt_command_unknown_error");
            }

        }

        private async Task<string[]> GetManyUUID(string[] name_list)
        {
            var list = new List<string>();

            foreach (var name in name_list)
            {
                var uuid = await RPGServerPersistenceManager.Instance.GetRoleUUIDByNameAsync(name, this);
                if (string.IsNullOrEmpty(uuid))
                {
                    list.Add(name);
                }
                else
                {
                    list.Add(uuid);
                }
            }
            return list.ToArray();
        }

        private Task<string> OnHandleGateServerOpen(JObject obj)
        {
            SyncGateServerOpen message = new SyncGateServerOpen();
            message.status = true;
            Provider.BroadcastWithType(ServerNames.GateServerType, message);

            return Task.FromResult(ResponseResult(true));
        }

        [RpcHandler(typeof(SystemGMServerOpenNotify))]
        public virtual void system_rpc_Handle(SystemGMServerOpenNotify shutdown)
        {
            this.Execute(() => OnHandleGateServerOpen(null));
        }
        public void CMDGateServerOpen()
        {
            this.Execute(() => OnHandleGateServerOpen(null));
        }
        public void CMDServerStop(string reason)
        {
            this.Execute(() =>
            {
                var msg = new DeepMMO.Server.SystemMessage.SystemShutdownNotify() { reason = reason };
                this.Provider.Broadcast(msg);
            });
        }



        #region CommonFunction

           
        private async Task<string> GetRoleUUID(string role_uuid)
        {
            if (role_uuid.Length < 36)
            {
                role_uuid = await RPGServerPersistenceManager.Instance.GetRoleUUIDByNameAsync(role_uuid, this);
            }

            return role_uuid;
        }

        #endregion

        //[RpcHandler(typeof(SyncConnectToGateNotify), ServerNames.ConnectServerType)]
        //public virtual void rpc_OnHandleConnector(SyncConnectToGateNotify msg)
        //{

        //}
    }
}
