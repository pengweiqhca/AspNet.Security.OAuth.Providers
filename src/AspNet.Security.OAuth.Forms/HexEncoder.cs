using Microsoft.Owin.Security.DataHandler.Encoder;

namespace AspNet.Security.OAuth.Forms
{
    class HexEncoder : ITextEncoder
    {
        public string Encode(byte[] data)
        {
            return data.ToHexadecimal();
        }

        public byte[] Decode(string text)
        {
            return text.ToBytesFromHexadecimal();
        }
    }
}
