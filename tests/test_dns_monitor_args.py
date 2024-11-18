import unittest
import subprocess
import os


class TestDNSMonitorArgs(unittest.TestCase):
    @staticmethod
    def run_dns_monitor(*args):
        """Helper function to run the dns-monitor with given arguments"""
        result = subprocess.run(['./dns-monitor'] + list(args),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        return result

    def test_missing_required_options(self):
        """Ensures the program exits with an error if neither -i nor -p is provided."""
        result = self.run_dns_monitor()
        self.assertIn(b"Error: You must specify either -i <interface> or -p <pcapfile>.", result.stderr)
        self.assertEqual(result.returncode, 2)

    def test_both_options_provided(self):
        """Ensures the program exits with an error if both -i and -p are provided simultaneously"""
        result = self.run_dns_monitor("-i", "en0", "-p", "sample.pcap")
        self.assertIn(b"Error: You cannot specify both -i <interface> and -p <pcapfile>.", result.stderr)
        self.assertEqual(result.returncode, 2)

    def test_invalid_option(self):
        """Verifies the program reports an error when an unsupported option is used."""
        result = self.run_dns_monitor("-x")
        self.assertIn(b"./dns-monitor: illegal option -- x", result.stderr)
        self.assertEqual(result.returncode, 2)

    def test_display_help(self):
        """Confirms the program displays the help message and exits successfully when -h is provided"""
        result = self.run_dns_monitor("-h")
        self.assertIn(b"Usage:", result.stdout)
        self.assertEqual(result.returncode, 0)

    def test_valid_pcap_option(self):
        """Ensures the program correctly processes a valid PCAP file with the -p option."""
        pcap_file = "tests/dns_simple_output_test.pcap"  # Ensure this is a valid PCAP file
        result = self.run_dns_monitor("-p", pcap_file)
        self.assertNotIn(b"Error", result.stderr)
        self.assertEqual(result.returncode, 0)

    def test_verbose_with_pcap(self):
        """Verifies the program operates correctly in verbose mode (-v) with a PCAP file."""
        pcap_file = "tests/dns_simple_output_test.pcap"
        result = self.run_dns_monitor("-v", "-p", pcap_file)
        self.assertNotIn(b"Error", result.stderr)
        self.assertEqual(result.returncode, 0)

    def test_combination_of_options(self):
        """Confirms the program handles valid combinations of options (-p, -v, -d, -t) and creates output files"""
        domains_file = "domains.txt"
        translations_file = "translations.txt"
        pcap_file = "tests/dns_simple_output_test.pcap"
        result = self.run_dns_monitor("-p", pcap_file, "-v", "-d", domains_file, "-t", translations_file)
        self.assertNotIn(b"Error", result.stderr)
        self.assertTrue(os.path.exists(domains_file))
        self.assertTrue(os.path.exists(translations_file))
        os.remove(domains_file)
        os.remove(translations_file)

    def test_invalid_pcap_file(self):
        """Ensures the program reports an error for a nonexistent PCAP file"""
        result = self.run_dns_monitor("-p", "nonexistent.pcap")
        self.assertIn(b"Error", result.stderr)
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_interface(self):
        """Verifies the program reports an error when an invalid network interface is specified"""
        result = self.run_dns_monitor("-i", "invalid_interface")
        self.assertIn(b"Error", result.stderr)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
