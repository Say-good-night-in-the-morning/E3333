using System;
using System.Threading;
using System.IO.Ports;

class RS232
{
    static bool _continue;
    static SerialPort _serialPort;
    public static void Main()
    {
        string identity;

        //创建串口对象
        _serialPort = new SerialPort();

        //设置相关参数
        _serialPort.PortName = SetPortName(_serialPort.PortName);//选择串口
        _serialPort.BaudRate = SetPortBaudRate(_serialPort.BaudRate);//设置串口的波特率
        _serialPort.Parity = SetPortParity(_serialPort.Parity);//设置奇偶校验位
        _serialPort.DataBits = SetPortDataBits(_serialPort.DataBits);//设置每个字节的标准数据位长度
        _serialPort.StopBits = SetPortStopBits(_serialPort.StopBits);//设置每个字节的停止标准位
        _serialPort.Handshake = SetPortHandshake(_serialPort.Handshake);//设置串行端口数据传输的握手协议

        _serialPort.ReadTimeout = 500;
        _serialPort.WriteTimeout = 500;

        _serialPort.Open();//打开串口
        _continue = true;

        Console.Write("若您需要将该串口设置为发送端，则输入‘1’；若设置为接收端，则输入‘2’(默认为发送方）:");
        identity=Console.ReadLine();

        if(identity=="2")
        {
            Read();
        }
        else
        {
            Write();
        }
        _serialPort.Close();
    }

    public static void Write()
    {
        Console.WriteLine("发送方（输入'Quit'时，则停止通信）");
        while (_continue)
        {
            StringComparer stringComparer = StringComparer.OrdinalIgnoreCase;

            string message = Console.ReadLine();//从控制台读取字符串
            if (stringComparer.Equals("quit", message))
            {
                _continue = false;
            }
            else
            {
                _serialPort.WriteLine(String.Format("[Sent{0}] {1}", DateTime.Now.ToString(), message));//将字符串和换行写入输出缓冲区
                Console.WriteLine("[Sent{0}] {1}", DateTime.Now.ToString(), message);
            }
        }
    }
    public static void Read()//接受消息
    {
        Console.WriteLine("接收方:");
        while(_continue)
        {
            try
            {
                string message = _serialPort.ReadLine();
             //Thread.Sleep(2000);
                Console.WriteLine("[RECV{0}]   {1}",DateTime.Now.ToString(),message);
            }
            catch (TimeoutException)
            { }
        }
    }
    public static string SetPortName(string defaultPortName)//选择串口
    {
        string portName;//串口名字
        Console.WriteLine("可以选用的串口： ");
        foreach (string s in SerialPort.GetPortNames())
        {
            Console.Write("    {0}    ", s);
        }
        Console.Write("\n请输入您选择的串口名称（若跳过，则默认为{0}）:", defaultPortName);
        portName = Console.ReadLine();

        if(portName==""||!(portName.ToLower()).StartsWith("com"))
        {
            portName = defaultPortName;
        }
        return portName;
    }

    public static int SetPortBaudRate(int defaultPortBaudRate)//设置波特率
    {
        string baudRate;

        Console.Write("请输入波特率(默认值为:{0})", defaultPortBaudRate);
        baudRate = Console.ReadLine();

        if (baudRate == "")
        {
            baudRate = defaultPortBaudRate.ToString();
        }

        return int.Parse(baudRate);
    }

    public static Parity SetPortParity(Parity defaultPortParity)//设置奇偶校验位
    {
        string parity;

        Console.WriteLine("可选择的奇偶校验位:");
        foreach (string s in Enum.GetNames(typeof(Parity)))
        {
            Console.Write("    {0}    ", s);
        }

        Console.Write("\n请输入奇偶校验位(默认值为:{0}):", defaultPortParity);
        parity = Console.ReadLine();

        if (parity == "")
        {
            parity = defaultPortParity.ToString();
        }

        return (Parity)Enum.Parse(typeof(Parity), parity, true);
    }

    public static int SetPortDataBits(int defaultDataBits)//设置每个字节的标准数据位长度
    {
        string dataBits;

        Console.Write("请输入每个字节的标准数据位长度（默认为:{0}）:", defaultDataBits);
        dataBits=Console.ReadLine();

        if (dataBits == "")
        {
            dataBits = defaultDataBits.ToString();
        }

        return int.Parse(dataBits.ToUpperInvariant());
    }

    public static StopBits SetPortStopBits(StopBits defaultStopBits)//设置每个字节的停止标准位
    {
        string stopBits;

        Console.WriteLine("可选择的标准停止位:\n    One    Two    OnePointFive");
        Console.Write("请输入标准停止位(默认值为:One)");
        stopBits=Console.ReadLine();

        if(stopBits=="")
        {
            stopBits = defaultStopBits.ToString();
        }

        return (StopBits)Enum.Parse(typeof(StopBits), stopBits, true);
    }

    public static Handshake SetPortHandshake(Handshake defaultPortHandshake)//设置串行端口数据传输的握手协议
    {
        string handshake;
        Console.WriteLine("可选择的握手协议:");
        foreach (string s in Enum.GetNames(typeof(Handshake)))
        {
            Console.Write("    {0}    ", s);
        }

        Console.Write("\n请输入握手协议（默认为{0}）:",defaultPortHandshake.ToString());
        handshake = Console.ReadLine();

        if(handshake=="")
        {
            handshake = defaultPortHandshake.ToString();
        }
        return (Handshake)Enum.Parse(typeof(Handshake), handshake, true);
    }
}

