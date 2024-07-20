using System;
using System.Diagnostics;
using System.IO;

class Program
{
    private const string logFileName = "log.txt";
    private const string banner = "=================================";
    private static readonly string filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\drivers\\CrowdStrike\\C-00000291.sys");

    static void Main(string[] args)
    {
        string logFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, logFileName);

        // Display banner when the program starts
        Console.WriteLine(banner);
        Console.WriteLine(" Delmonting CrowdStrike ");
        Console.WriteLine(banner);

        try
        {
            Log("Configuring safe mode boot...", logFilePath);
            // Configure safe mode boot
            SetSafeMode(true, logFilePath);

            Log("Attempting to delete file: " + filePath, logFilePath);
            // Delete the file
            DeleteFile(filePath, logFilePath);

            Log("Restoring normal boot...", logFilePath);
            // Configure normal boot
            SetSafeMode(false, logFilePath);

            Log("Process completed successfully.", logFilePath);
        }
        catch (Exception ex)
        {
            Log("Error: " + ex.Message, logFilePath);
        }
    }

    static void SetSafeMode(bool enable, string logFilePath)
    {
        try
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo("bcdedit.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                Arguments = enable ? "/set {default} safeboot minimal" : "/deletevalue {default} safeboot"
            };

            Process process = Process.Start(processStartInfo);
            process.WaitForExit();

            Log("Safe mode configured: " + enable, logFilePath);
        }
        catch (Exception ex)
        {
            Log("Error configuring safe mode: " + ex.Message, logFilePath);
            throw;
        }
    }

    static void DeleteFile(string filePath, string logFilePath)
    {
        try
        {
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
                Log("File deleted: " + filePath, logFilePath);
            }
            else
            {
                Log("File not found: " + filePath, logFilePath);
            }
        }
        catch (Exception ex)
        {
            Log("Error deleting file: " + ex.Message, logFilePath);
            throw;
        }
    }

    static void Log(string message, string logFilePath)
    {
        try
        {
            using (StreamWriter writer = new StreamWriter(logFilePath, true))
            {
                writer.WriteLine($"{DateTime.Now}: {message}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error writing to log: " + ex.Message);
        }
    }
}

