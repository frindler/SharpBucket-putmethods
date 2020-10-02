﻿using System;
using System.Linq;
using System.Net;
using SharpBucket.V2;
using SharpBucket.V2.Pocos;

namespace SharpBucketCli
{
    /// <summary>
    /// This program is both a sample and a tool to help SharpBucket developers to maintain their test account.
    /// When developing on SharpBucket you may quickly generate a lot of repositories which are not cleaned up because
    /// due to broken unit test execution during a debug session, or writing new unit tests that leak, and so on.
    /// And deleting a lot of repositories with the web interface is ungrateful... 
    /// </summary>
    public class Program
    {
        public static int Main(string[] args)
        {
            try
            {
                if (args.Length == 0)
                {
                    var program = new Program();
                    program.ListenToInteractiveCommands();
                    return 0;
                }

                Console.Error.WriteLine("Non interactive mode is not yet implemented");
                return -1;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e);
                return -1;
            }
        }

        private SharpBucketV2 SharpBucket { get; }

        /// <summary>
        /// The account on which I am currently logged.
        /// </summary>
        private User Me { get; set; }

        /// <summary>
        /// The account On which I am currently working on.
        /// </summary>
        private User Account { get; set; }

        private Program()
        {
            this.SharpBucket = new SharpBucketV2();
        }

        private void ListenToInteractiveCommands()
        {
            Console.WriteLine("Welcome to the interactive mode of the SharpBucket Command Line Interface");
            this.UseEnvironmentCredentials();
            while (true)
            {
                Console.Write($"{this.Me?.nickname}:{this.Account?.display_name}> ");
                var command = Console.ReadLine() ?? string.Empty;
                var args = command.Split(' ');
                var verb = args[0];
                var options = args.Skip(1).ToArray();

                try
                {
                    switch (verb)
                    {
                        case "help": Help(); break;
                        case "clean": Clean(); break;
                        case "switch": Switch(options); break;
                        case "exit": return;
                        default: Console.WriteLine("Unrecognized command. Type help to get help about existing commands"); break;
                    }
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine(e);
                }
            }
        }

        private void UseEnvironmentCredentials()
        {
            var consumerKey = Environment.GetEnvironmentVariable("SB_CONSUMER_KEY");
            var consumerKeySecret = Environment.GetEnvironmentVariable("SB_CONSUMER_SECRET_KEY");

            if (!string.IsNullOrEmpty(consumerKey) && !string.IsNullOrEmpty(consumerKeySecret))
            {
                this.SharpBucket.OAuth2ClientCredentials(consumerKey, consumerKeySecret);
                Account = Me = this.SharpBucket.UserEndPoint().GetUser();
                Console.WriteLine($"You have been automatically logged as {Me.display_name}");
            }
        }

        private static void Help()
        {
            Console.WriteLine("Available commands are:");
            Console.WriteLine("  clean     : Delete all the repositories owned by the current account.");
            Console.WriteLine("              Useful to clean up a test account overwhelmed by repositories not");
            Console.WriteLine("              correctly cleaned up by the unit tests.");
            Console.WriteLine();
            Console.WriteLine("  switch   : Switch to another account. This could be a user or a team.");
            Console.WriteLine();
            Console.WriteLine("  exit     : Exit the interactive mode.");
            Console.WriteLine();
            Console.WriteLine("  help     : Print this help.");
        }

        private void Clean()
        {
            if (this.Me == null)
            {
                Console.Error.WriteLine("You must be logged to execute that command");
                return;
            }

            var repositoriesEndPoint = this.SharpBucket.RepositoriesEndPoint();
            var repositories = repositoriesEndPoint.RepositoriesResource(this.Account.uuid).ListRepositories();
            foreach (var repository in repositories)
            {
                var repositoryResource = repositoriesEndPoint.RepositoryResource(this.Account.uuid, repository.slug);
                repositoryResource.DeleteRepository();
                Console.WriteLine($"Repository {this.Account.nickname ?? this.Account.display_name}/{repository.slug} has been deleted");
            }
        }

        private void Switch(string[] args)
        {
            if (args.Length != 2)
            {
                Console.Error.WriteLine("Invalid command arguments");
                return;
            }

            switch (args[0])
            {
                case "--account":
                    SwitchAccount(args[1]);
                    break;
                default:
                    Console.Error.WriteLine("Invalid command arguments");
                    break;
            }
        }

        private void SwitchAccount(string accountName)
        {
            try
            {
                this.Account = SharpBucket.UsersEndPoint(accountName).GetProfile();
            }
            catch (BitbucketV2Exception e)
                when(e.HttpStatusCode == HttpStatusCode.NotFound)
            {
                // The given accountName do not seem to be a simple user, so try as a team
                this.Account = SharpBucket.TeamsEndPoint().TeamResource(accountName).GetProfile();
            }
        }
    }
}
