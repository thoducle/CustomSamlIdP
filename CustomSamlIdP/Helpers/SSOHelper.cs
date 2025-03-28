using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace CustomSamlIdP.Helpers
{
    public class SSOHelper
    {
        public static string ModifyAndResignSamlResponse(string base64SamlResponse, string pfxPath, string pfxPassword)
        {
            var cert = new X509Certificate2(pfxPath, pfxPassword,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            string xml = Encoding.UTF8.GetString(Convert.FromBase64String(base64SamlResponse));
            var doc = new XmlDocument { PreserveWhitespace = true };
            doc.LoadXml(xml);

            var ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
            ns.AddNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");
            ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

            var responseNode = doc.DocumentElement;
            var assertionNode = doc.SelectSingleNode("//saml2:Assertion", ns) as XmlElement;

            // Remove existing signatures
            RemoveSignature(responseNode, ns);
            RemoveSignature(assertionNode, ns);

            // Add new attribute
            var attrStmt = assertionNode.SelectSingleNode("saml2:AttributeStatement", ns) as XmlElement;
            if (attrStmt == null)
            {
                attrStmt = doc.CreateElement("saml2", "AttributeStatement", ns.LookupNamespace("saml2"));
                assertionNode.AppendChild(attrStmt);
            }

            var newAttr = doc.CreateElement("saml2", "Attribute", ns.LookupNamespace("saml2"));
            newAttr.SetAttribute("Name", "customAttribute");

            var attrVal = doc.CreateElement("saml2", "AttributeValue", ns.LookupNamespace("saml2"));
            attrVal.InnerText = "customValue";
            newAttr.AppendChild(attrVal);
            attrStmt.AppendChild(newAttr);

            // Sign Assertion
            SignXmlElement(assertionNode, cert, "saml2:Issuer", ns);

            // Sign Response
            SignXmlElement(responseNode, cert, "saml2p:Status", ns);

            return Convert.ToBase64String(Encoding.UTF8.GetBytes(doc.OuterXml));
        }

        private static void RemoveSignature(XmlElement parent, XmlNamespaceManager ns)
        {
            var sig = parent?.SelectSingleNode("ds:Signature", ns);
            sig?.ParentNode?.RemoveChild(sig);
        }

        private static void SignXmlElement(XmlElement targetElement, X509Certificate2 cert, string insertAfterTag, XmlNamespaceManager ns)
        {
            var id = targetElement.GetAttribute("ID");
            if (string.IsNullOrEmpty(id)) throw new Exception("ID attribute is required for signing");

            var signedXml = new SignedXml(targetElement)
            {
                SigningKey = cert.GetRSAPrivateKey()
            };

            var reference = new Reference { Uri = "#" + id };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);

            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature();
            var signature = signedXml.GetXml();

            var insertAfter = targetElement.SelectSingleNode(insertAfterTag, ns);
            targetElement.InsertAfter(signature, insertAfter);
        }

    }
}
