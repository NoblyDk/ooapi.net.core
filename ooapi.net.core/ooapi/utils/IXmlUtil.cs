using System.Threading.Tasks;
using System.Xml;

namespace org.openoces.ooapi.utils
{
    public interface IXmlUtil
    {
        Task<XmlDocument> LoadXml(string xml);
    }
}