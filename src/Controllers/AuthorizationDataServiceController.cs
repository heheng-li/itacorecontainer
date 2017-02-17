using System;
using System.Collections.Generic;
using System.Linq;
using System.Data;
using System.Data.SqlClient;
using System.Text;
using System.Xml;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace ItaCore.Controllers
{
    public class DatabaseOptions
    {
        public string ConnectionString { get; set; }
    }

    [Authorize]
    [Route("api/[controller]")]
    public class AuthorizationDataServiceController : Controller
    {
        readonly IOptions<DatabaseOptions> options;
        public AuthorizationDataServiceController(IOptions<DatabaseOptions> options)
        {
            this.options = options;
        }

        // GET: api/AuthorizationDataService
        [HttpGet]
        public string SearchSubjectAuthorizationData()
        {
            var qs = Request.Query;
            string subjectkey = GetKey("subjectkey", qs);
            string realm = GetKey("realm", qs);
            string npd = GetKey("npd", qs);
            string role = GetKey("role", qs);
            string roletag = GetKey("roletag", qs);
            bool indirectassignment = bool.Parse(GetKey("indirectassignment", qs));

            var parameters = new[] {
                new SqlParameter("@pi_NPDName", npd),
                new SqlParameter("@pi_AuthenticationRealmName", realm),
                new SqlParameter("@pi_SubjectKey", subjectkey),
                new SqlParameter("@pi_RoleName", role),
                new SqlParameter("@pi_RoleTag", roletag),
                new SqlParameter("@pi_ReturnIndirectAssignments", indirectassignment)
            };

            var ds = ExecuteStoredProcQuery(options.Value.ConnectionString, "RA.GetSubjectAuthorizationData", parameters);

            return RenderSearchSubjectAuthorizationDataXml(ds, subjectkey, realm, npd, role, roletag, indirectassignment);
        }

        static string GetKey(string key, IQueryCollection qs)
        {
            if (!qs.ContainsKey(key))
            {
                return null;
            }
            var v = qs[key].ToArray();
            if (v.Length == 0)
            {
                return null;
            }
            return v[0];
        }

        static List<Dictionary<string, object>> ExecuteStoredProcQuery(string connString, string spName, SqlParameter[] parameters)
        {
            try
            {
                var ds = new List<Dictionary<string, object>>();

                using (var conn = new SqlConnection(connString))
                {
                    conn.Open();

                    foreach (var p in parameters)
                    {
                        if (p.Value == null)
                        {
                            p.Value = DBNull.Value;
                        }
                    }

                    var cmd = new SqlCommand
                    {
                        CommandType = CommandType.StoredProcedure,
                        CommandText = spName,
                        Connection = conn
                    };
                    cmd.Parameters.AddRange(parameters);

                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            ds.Add(Enumerable.Range(0, reader.FieldCount).ToDictionary(reader.GetName, reader.GetValue));
                        }
                    }
                }

                return ds;
            }
            catch (SqlException e)
            {
                throw new Exception(e.Message);
            }
        }

        class AttributeNameNodeAuthorizationData
        {
            public readonly HashSet<string> Values = new HashSet<string>();
        }

        class AttributeSetNodeAuthorizationData
        {
            public readonly Dictionary<string, AttributeNameNodeAuthorizationData> AttributeNameNodes = new Dictionary<string, AttributeNameNodeAuthorizationData>();
        }

        class PermissionData
        {
            public string ResourceName;
            public string ResourceOperation;
            public string ExternalIdentifier;
        }

        class RoleNodeAuthorizationData
        {
            public readonly HashSet<string> RoleTags = new HashSet<string>();
            public readonly Dictionary<string, PermissionData> Permissions = new Dictionary<string, PermissionData>();
            public readonly Dictionary<string, AttributeSetNodeAuthorizationData> AttributeSetNodes = new Dictionary<string, AttributeSetNodeAuthorizationData>();
        }

        static string RenderSearchSubjectAuthorizationDataXml(
            List<Dictionary<string, object>> ds,
            string subjectkey,
            string realm,
            string npd,
            string role,
            string roletag,
            bool indirectassignment
            )
        {
            if (ds.Count == 0)
            {
                return string.Empty;
            }

            var sb = new StringBuilder();
            using (var xw = XmlWriter.Create(sb))
            {
                xw.WriteStartDocument();
                xw.WriteStartElement("SearchSubjectAuthorizationData");

                xw.WriteAttributeString("NamedProtectionDomain", npd);
                xw.WriteAttributeString("SubjectKey", subjectkey);
                xw.WriteAttributeString("AuthenticationRealmName", realm);
                xw.WriteAttributeString("RoleName", role);
                xw.WriteAttributeString("RoleTag", roletag);
                xw.WriteAttributeString("ReturnIndirectAssignments", indirectassignment.ToString());
                xw.WriteStartElement("SubjectAuthorizationData");

                var roles = new Dictionary<string, RoleNodeAuthorizationData>();

                foreach (var row in ds)
                {
                    string roleName = (string)row["RoleName"];

                    RoleNodeAuthorizationData currentRoleNode;

                    if (!roles.ContainsKey(roleName))
                    {
                        currentRoleNode = new RoleNodeAuthorizationData();
                        roles.Add(roleName, currentRoleNode);
                    }
                    else
                    {
                        currentRoleNode = roles[roleName];
                    }

                    string attributeSet = (string)row["SubjectRoleConstraintValueSet"];

                    if (!string.IsNullOrEmpty(attributeSet))
                    {
                        AttributeSetNodeAuthorizationData currentAttributeSetNode;

                        if (!currentRoleNode.AttributeSetNodes.ContainsKey(attributeSet))
                        {
                            currentAttributeSetNode = new AttributeSetNodeAuthorizationData();
                            currentRoleNode.AttributeSetNodes.Add(attributeSet, currentAttributeSetNode);
                        }
                        else
                        {
                            currentAttributeSetNode = currentRoleNode.AttributeSetNodes[attributeSet];
                        }

                        string attributeName = (string)row["SubjectRoleConstraintAttributeName"];

                        if (!string.IsNullOrEmpty(attributeName))
                        {
                            AttributeNameNodeAuthorizationData currentAttributeNameNode;

                            if (!currentAttributeSetNode.AttributeNameNodes.ContainsKey(attributeName))
                            {
                                currentAttributeNameNode = new AttributeNameNodeAuthorizationData();
                                currentAttributeSetNode.AttributeNameNodes.Add(attributeName, currentAttributeNameNode);
                            }
                            else
                            {
                                currentAttributeNameNode = currentAttributeSetNode.AttributeNameNodes[attributeName];
                            }

                            string value = (string)row["SubjectRoleConstraintValue"];

                            if (!currentAttributeNameNode.Values.Contains(value))
                            {
                                currentAttributeNameNode.Values.Add(value);
                            }
                        }
                    }

                    string roleTag = (string)row["RoleTag"];

                    if (!string.IsNullOrEmpty(roleTag))
                    {
                        if (!currentRoleNode.RoleTags.Contains(roleTag))
                        {
                            currentRoleNode.RoleTags.Add(roleTag);
                        }
                    }

                    string resourceName = (string)row["ResourceName"];

                    if (!string.IsNullOrEmpty(resourceName))
                    {
                        string resourceOperation = (string)row["ResourceOperation"];

                        var permission = resourceName + '\r' + resourceOperation;

                        if (!currentRoleNode.Permissions.ContainsKey(permission))
                        {
                            string externalIdentifier = (string)row["ExternalIdentifier"];

                            currentRoleNode.Permissions.Add(
                                permission,
                                new PermissionData
                                {
                                    ResourceName = resourceName,
                                    ResourceOperation = resourceOperation,
                                    ExternalIdentifier = externalIdentifier
                                }
                                );
                        }
                    }
                }

                foreach (var r in roles)
                {
                    string roleName = r.Key;
                    var roleData = r.Value;

                    xw.WriteStartElement("Role");
                    xw.WriteAttributeString("Name", roleName);

                    xw.WriteStartElement("Tags");
                    foreach (var rt in r.Value.RoleTags)
                    {
                        xw.WriteStartElement("Tag");
                        xw.WriteAttributeString("Value", rt);
                        xw.WriteEndElement();
                    }
                    xw.WriteEndElement();

                    foreach (var p in r.Value.Permissions)
                    {
                        xw.WriteStartElement("Permission");
                        xw.WriteAttributeString("ResourceName", p.Value.ResourceName);
                        xw.WriteAttributeString("ResourceOperation", p.Value.ResourceOperation);
                        xw.WriteAttributeString("ExternalIdentifier", p.Value.ExternalIdentifier);
                        xw.WriteEndElement();
                    }

                    foreach (var attrset in r.Value.AttributeSetNodes)
                    {
                        xw.WriteStartElement("AttributeSet");
                        xw.WriteAttributeString("ID", attrset.Key);

                        foreach (var attr in attrset.Value.AttributeNameNodes)
                        {
                            xw.WriteStartElement("Attribute");
                            xw.WriteAttributeString("Name", attr.Key);

                            foreach (var v in attr.Value.Values)
                            {
                                xw.WriteElementString("Value", v);
                            }

                            xw.WriteEndElement();
                        }

                        xw.WriteEndElement();
                    }

                    xw.WriteEndElement();
                }

                xw.WriteEndElement();

                xw.WriteEndElement();
                xw.WriteEndDocument();
            }

            return sb.ToString();
        }
    }
}
