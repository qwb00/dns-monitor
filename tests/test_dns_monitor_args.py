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
        """Test that program exits with an error when neither -i nor -p is provided"""
        result = self.run_dns_monitor()
        self.assertIn(b"Error: You must specify either -i <interface> or -p <pcapfile>.", result.stderr)
        self.assertEqual(result.returncode, 2)

    def test_both_options_provided(self):
        """Test that program exits with an error when both -i and -p are provided."""
        result = self.run_dns_monitor("-i", "en0", "-p", "sample.pcap")
        self.assertIn(b"Error: You cannot specify both -i <interface> and -p <pcapfile>.", result.stderr)
        self.assertEqual(result.returncode, 2)

    def test_invalid_option(self):
        """Test that program exits with an error when an invalid option is provided."""
        result = self.run_dns_monitor("-x")
        self.assertIn(b"./dns-monitor: illegal option -- x", result.stderr)
        self.assertEqual(result.returncode, 2)

    def test_display_help(self):
        """Test that program displays help information when -h is provided."""
        result = self.run_dns_monitor("-h")
        self.assertIn(b"Usage:", result.stdout)
        self.assertEqual(result.returncode, 0)

    def test_valid_pcap_option(self):
        """Test that program runs correctly with -p <pcapfile>."""
        pcap_file = "tests/dns_simple_output_test.pcap"  # Ensure this is a valid PCAP file
        result = self.run_dns_monitor("-p", pcap_file)
        self.assertNotIn(b"Error", result.stderr)
        self.assertEqual(result.returncode, 0)

    def test_verbose_with_pcap(self):
        """Test that program runs correctly with -v and -p <pcapfile>."""
        pcap_file = "tests/dns_simple_output_test.pcap"
        result = self.run_dns_monitor("-v", "-p", pcap_file)
        self.assertNotIn(b"Error", result.stderr)
        self.assertEqual(result.returncode, 0)

    def test_combination_of_options(self):
        """Test that program handles a combination of valid options"""
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
        """Test that program exits with an error for an invalid PCAP file"""
        result = self.run_dns_monitor("-p", "nonexistent.pcap")
        self.assertIn(b"Error", result.stderr)
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_interface(self):
        """Test that program exits with an error for an invalid network interface"""
        result = self.run_dns_monitor("-i", "invalid_interface")
        self.assertIn(b"Error", result.stderr)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
