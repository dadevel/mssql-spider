using System.Data;
using System.Data.SqlTypes;
using System.Diagnostics;
using Microsoft.SqlServer.Server;

// compilation: C:\Windows\Microsoft.NET\Framework64\v4*\csc.exe /target:library .\SharpProcedure.cs

public class StoredProcedures {
    [SqlProcedure]
    public static SqlInt32 Run(SqlString file, SqlString args) {
        Process p = new Process();
        p.StartInfo.FileName = file.ToString();
        p.StartInfo.Arguments = args.ToString();
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.RedirectStandardError = true;
        p.StartInfo.CreateNoWindow = true;
        p.Start();
        SqlDataRecord r = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, -1));
        SqlContext.Pipe.SendResultsStart(r);
        string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        r.SetString(0, o);
        SqlContext.Pipe.SendResultsRow(r);
        SqlContext.Pipe.SendResultsEnd();
        p.WaitForExit();
        return new SqlInt32(p.ExitCode);
    }
};
